/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#define _GNU_SOURCE

#include <assert.h>
#include <string.h>

#include <poll.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <linux/net.h>

#include "rec_process_event.h"
#include "rec_sched.h"
#include "handle_signal.h"

#include "../replayer/replayer.h" /* for emergency_debug() */
#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/ipc.h"
#include "../share/trace.h"
#include "../share/sys.h"
#include "../share/task.h"
#include "../share/util.h"
#include "../share/syscall_buffer.h"

#define PTRACE_EVENT_NONE			0
static struct flags rr_flags_ = { 0 };
static bool filter_on_ = FALSE;

static void rec_init_scratch_memory(struct context *ctx)
{
	const int scratch_size = 512 * sysconf(_SC_PAGE_SIZE);
	/* initialize the scratchpad for blocking system calls */
	struct current_state_buffer state;

	prepare_remote_syscalls(ctx, &state);
	ctx->scratch_ptr = (void*)remote_syscall6(
		ctx, &state, SYS_mmap2,
		0, scratch_size,
		PROT_READ | PROT_WRITE | PROT_EXEC, /* EXEC, really? */
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ctx->scratch_size = scratch_size;
	finish_remote_syscalls(ctx, &state);

	// record this mmap for the replay
	struct user_regs_struct orig_regs;
	read_child_registers(ctx->tid,&orig_regs);
	int eax = orig_regs.eax;
	orig_regs.eax = (uintptr_t)ctx->scratch_ptr;
	write_child_registers(ctx->tid,&orig_regs);
	struct mmapped_file file = {0};
	file.time = get_global_time();
	file.tid = ctx->tid;
	file.start = ctx->scratch_ptr;
	file.end = ctx->scratch_ptr + scratch_size;
	sprintf(file.filename,"scratch for thread %d",ctx->tid);
	record_mmapped_file_stats(&file);
	int event = ctx->event;
	ctx->event = USR_INIT_SCRATCH_MEM;
	record_event(ctx,STATE_SYSCALL_EXIT);
	ctx->event = event;
	orig_regs.eax = eax;
	write_child_registers(ctx->tid,&orig_regs);
}

static void cont_nonblock(struct context *ctx)
{
	sys_ptrace_syscall(ctx->tid);
}

static int wait_nonblock(struct context *ctx)
{
	int ret = sys_waitpid_nonblock(ctx->tid, &(ctx->status));

	if (ret) {
		assert(WIFEXITED(ctx->status) == 0);
		handle_signal(&rr_flags_, ctx);
		ctx->event = read_child_orig_eax(ctx->tid);
	}
	return ret;
}

static void canonicalize_event(struct context* ctx)
{
	if (ctx->event == RRCALL_init_syscall_buffer) {
		ctx->event = (-ctx->event | RRCALL_BIT);
	}
}

/**
 * Continue the child until it gets a signal or a ptrace event
 */
static void cont_block(struct context *ctx)
{
	sys_ptrace(PTRACE_CONT, ctx->tid, 0, 0);
	sys_waitpid(ctx->tid, &ctx->status);
	assert(signal_pending(ctx->status) != SIGTRAP);
	read_child_registers(ctx->tid, &(ctx->regs));
	ctx->event = ctx->regs.orig_eax;
	canonicalize_event(ctx);
	handle_signal(&rr_flags_, ctx);
}

/**
 * Continue the child until it gets a signal, a syscall or a ptrace event
 */
static void cont_syscall_block(struct context *ctx)
{
	sys_ptrace(PTRACE_SYSCALL, ctx->tid, 0, 0);
	sys_waitpid(ctx->tid, &ctx->status);
	read_child_registers(ctx->tid, &(ctx->regs));
	ctx->event = ctx->regs.orig_eax;
	canonicalize_event(ctx);
	handle_signal(&rr_flags_, ctx);
}

uintptr_t progress;

static void handle_ptrace_event(struct context **ctx_ptr)
{
	/* handle events */
	int event = GET_PTRACE_EVENT((*ctx_ptr)->status);
	debug("  %d: handle_ptrace_event %d: syscall %s",
	      (*ctx_ptr)->tid, event, syscallname((*ctx_ptr)->event));
	switch (event) {

	case PTRACE_EVENT_NONE:
	{
		break;
	}

	case PTRACE_EVENT_VFORK_DONE:
	{
		rec_process_syscall(*ctx_ptr, (*ctx_ptr)->event, rr_flags_);
		record_event((*ctx_ptr), STATE_SYSCALL_EXIT);
		(*ctx_ptr)->exec_state = EXEC_STATE_START;
		(*ctx_ptr)->switchable = 1;
		/* issue an additional continue, since the process was stopped by the additional ptrace event */
		cont_syscall_block(*ctx_ptr);
		record_event((*ctx_ptr), STATE_SYSCALL_EXIT);
		break;
	}

	case PTRACE_EVENT_CLONE:
	case PTRACE_EVENT_FORK:
	case PTRACE_EVENT_VFORK:
	{
		/* get new tid, register at the scheduler and setup HPC */
		int new_tid = sys_ptrace_getmsg((*ctx_ptr)->tid);

		/* ensure that clone was successful */
		assert(read_child_eax((*ctx_ptr)->tid) != -1);

		/* wait until the new thread is ready */
		sys_waitpid(new_tid, &((*ctx_ptr)->status));
		rec_sched_register_thread(&rr_flags_,
					  (*ctx_ptr)->tid, new_tid);

		/* execute an additional ptrace_sysc((0xFF0000 & status) >> 16), since we setup trace like that.
		 * If the event is vfork we must no execute the cont_block, since the parent sleeps until the
		 * child has finished */
		if (event == PTRACE_EVENT_VFORK) {
			(*ctx_ptr)->exec_state = EXEC_STATE_IN_SYSCALL;
			(*ctx_ptr)->switchable = 1;
			record_event((*ctx_ptr), STATE_SYSCALL_ENTRY);
			cont_nonblock((*ctx_ptr));
		} else {
			cont_syscall_block((*ctx_ptr));
		}
		break;
	}

	case PTRACE_EVENT_EXEC:
	{
		record_event(*ctx_ptr, STATE_SYSCALL_ENTRY);
		cont_syscall_block(*ctx_ptr);
		rec_init_scratch_memory(*ctx_ptr);
		assert(signal_pending((*ctx_ptr)->status) == 0);
		break;
	}

	case PTRACE_EVENT_EXIT:
	{
		(*ctx_ptr)->event = USR_EXIT;
		record_event((*ctx_ptr), STATE_SYSCALL_EXIT);
		rec_sched_deregister_thread(ctx_ptr);
		/*
		 * This is a dirty workaround: If a thread issues the exit_group system call, it may happen
		 * that the thread that gets scheduled after this one is stopped, so rr will let it continue,
		 * but in fact it is "not  yet  fully  dead, but already refusing ptrace requests".
		 * TODO: track thread group of threads and handle this case properly by deregistering them
		 * directly
		 */
		usleep(100);
		break;
	}

	default:
	{
		log_err("Unknown ptrace event: %x -- bailing out", event);
		sys_exit();
		break;
	}

	} /* end switch */
}

#define debug_exec_state(_msg, _ctx)			       \
	debug(_msg ": pevent=%d, sig=%d, event=%s",	       \
	      GET_PTRACE_EVENT(_ctx->status), _ctx->child_sig, \
	      strevent(_ctx->event))

static void try_advance_syscall(struct context** ctxp)
{
	struct context* ctx = *ctxp;

	switch (ctx->exec_state) {
	case EXEC_STATE_ENTRY_SYSCALL:
		debug_exec_state("EXEC_SYSCALL_ENTRY", ctx);

		/* continue and execute the system call */
		ctx->switchable = rec_prepare_syscall(ctx, ctx->event);
		cont_nonblock(ctx);

		debug_exec_state("after cont", ctx);

		ctx->exec_state = EXEC_STATE_IN_SYSCALL;
		return;

	case EXEC_STATE_IN_SYSCALL: {
		int ret;

		debug_exec_state("EXEC_IN_SYSCALL", ctx);

		ret = wait_nonblock(ctx);

		debug_exec_state("  after wait", ctx);

		if (ret) {
			ctx->exec_state = EXEC_STATE_IN_SYSCALL_DONE;
			ctx->switchable = 0;
		}
		return;
	}

	case EXEC_STATE_IN_SYSCALL_DONE: {
		struct user_regs_struct regs;
		int syscall, retval;

		debug_exec_state("EXEC_SYSCALL_DONE", ctx);

		assert(signal_pending(ctx->status) == 0);

		read_child_registers(ctx->tid,&regs);
		syscall = regs.orig_eax;
		retval = regs.eax;
		if (0 <= syscall
		    && SYS_clone != syscall
		    && SYS_exit_group != syscall && SYS_exit != syscall
		    && -ENOSYS == retval) {
			log_err("Exiting syscall %s, but retval is -ENOSYS, usually only seen at entry",
				syscallname(syscall));
			emergency_debug(ctx);
		}

		debug("  orig_eax is %d (%s)", syscall, syscallname(syscall));

		/* we received a signal while in the system call and
		 * send it right away*/
		/* we have already sent the signal and process
		 * sigreturn */
		assert(ctx->event != SYS_sigreturn);

		/* if the syscall is about to be restarted, save the
		 * last syscall performed by it. */
		if (syscall != SYS_restart_syscall
		    && SYSCALL_WILL_RESTART(retval)) {
			debug("  retval %d, will restart %s",
			      retval, syscallname(syscall));
			ctx->last_syscall = syscall;
			ctx->will_restart = 1;
		}

		handle_ptrace_event(ctxp);
		ctx = *ctxp;
		if (!ctx || ctx->event == SYS_vfork) {
			return;
		}

		assert(signal_pending(ctx->status) != SIGTRAP);
		/* a syscall_restart ending is equivalent to the
		 * restarted syscall ending */
		if (syscall == SYS_restart_syscall) {
			syscall = ctx->last_syscall;
			ctx->event = syscall;
			debug("  exiting restarted %s", syscallname(syscall));
		}
		/* no need to process the syscall in case its
		 * restarted this will be done in the exit from the
		 * restart_syscall */
		if (!SYSCALL_WILL_RESTART(retval)) {
			rec_process_syscall(ctx, syscall, rr_flags_);
		}
		record_event(ctx, STATE_SYSCALL_EXIT);
		ctx->exec_state = EXEC_STATE_START;
		ctx->switchable = 1;
		if (ctx->desched_rec) {
			assert(ctx->syscallbuf_hdr->abort_commit);
			/* If this syscall was interrupted by a
			 * desched event, then just after the finished
			 * syscall there will be an ioctl() to disarm
			 * the event that we won't record here.  So
			 * save a breadcrumb so that replay knows to
			 * expect it and skip over it. */
			ctx->desched_rec = NULL;
			record_synthetic_event(ctx, USR_DISARM_DESCHED);
		}
		return;
	}

	default:
		fatal("Unknown exec state %d", ctx->exec_state);
	}
}

void record(const struct flags* rr_flags)
{
	rr_flags_ = *rr_flags;
	struct context *ctx = NULL;

	while (rec_sched_get_num_threads() > 0) {
		ctx = rec_sched_get_active_thread(&rr_flags_, ctx);

		debug("Active task is %d", ctx->tid);

		if (ctx->scratch_ptr == NULL) {
			rec_init_scratch_memory(ctx);
		}

		if (ctx->exec_state > EXEC_STATE_START) {
			try_advance_syscall(&ctx);
			continue;
		}
		assert(EXEC_STATE_START == ctx->exec_state);

		debug_exec_state("EXEC_START", ctx);

		if (progress++ % 10000 == 0) {
			fprintf(stderr,".");
			fflush(stdout);
		}

		if (ctx->will_restart && filter_on_) {
			debug("  advancing to restarted %s",
			      syscallname(ctx->last_syscall));
		}

		if (!ctx->will_restart && filter_on_) {
			/* When the seccomp filter is on, instead of
			 * capturing syscalls by using PTRACE_SYSCALL,
			 * the filter will generate the ptrace
			 * events. This means we allow the process to
			 * run using PTRACE_CONT, and rely on the
			 * seccomp filter to generate the special
			 * PTRACE_EVENT_SECCOMP event once a syscall
			 * happens.  This event is handled here by
			 * simply allowing the process to continue to
			 * the actual entry point of the syscall
			 * (using cont_syscall_block()) and then using
			 * the same logic as before. */
			cont_block(ctx);
		} else {
			/* We won't receive PTRACE_EVENT_SECCOMP
			 * events until the seccomp filter is
			 * installed by the syscall_buffer lib in the
			 * child, therefore we must record in the
			 * traditional way (with PTRACE_SYSCALL) until
			 * it is installed. */
			cont_syscall_block(ctx);
		}
		ctx->will_restart = 0;

		debug_exec_state("  first trap", ctx);

		/* we must disallow the context switch here! */
		ctx->switchable = 0;

		int ptrace_event = GET_PTRACE_EVENT(ctx->status);
		if (ptrace_event == PTRACE_EVENT_SECCOMP
		    || ptrace_event == PTRACE_EVENT_SECCOMP_OBSOLETE) {
			filter_on_ = TRUE;
			if (ctx->event < 0) {
				/* Finish handling of the signal
				 * first */
				record_event(ctx,STATE_SYSCALL_ENTRY);
			}
			/* We require an extra continue, to get to the
			 * actual syscall
			 *
			 * TODO: What if there's a signal in between? */
			cont_syscall_block(ctx);

			debug_exec_state("  post-seccomp trap", ctx);
		} else if (ptrace_event == PTRACE_EVENT_CLONE
			   || ptrace_event == PTRACE_EVENT_FORK) {
			/* clone(),fork() are handled differently with
			 * seccomp
			 *
			 * TODO: vfork() */
			debug("Handling ptrace event: %d",
			      GET_PTRACE_EVENT(ctx->status));
			record_event(ctx, STATE_SYSCALL_ENTRY);
			handle_ptrace_event(&ctx);
			rec_process_syscall(ctx,SYS_clone,rr_flags_);
			record_event(ctx, STATE_SYSCALL_EXIT);
			continue;
		} else if (ptrace_event) {
			/* TODO: this should only be the exit event
			 * really... */
			debug("Handling ptrace event: %d",
			      GET_PTRACE_EVENT(ctx->status));
			record_event(ctx, STATE_SYSCALL_EXIT);
			handle_ptrace_event(&ctx);
			continue;
		}

		if (ctx->event < 0) {
			/* handle_signal() took care of recording any
			 * events related to the (pseudo-)signal. */
			/* TODO: is there any reason not to enable
			 * switching after signals are delivered? */
			ctx->switchable = (ctx->event == SIG_SEGV_RDTSC
					   || ctx->event == USR_SCHED);
			continue;
		} else if (ctx->event == SYS_sigreturn
			   || ctx->event == SYS_rt_sigreturn) {
			int orig_event = ctx->event;
			/* These system calls never return; we remain
			 * in the same execution state */
			/* we record the sigreturn event here, since
			 * we have to do another ptrace_cont to fully
			 * process the sigreturn system call. */
			debug("  sigreturn");
			record_event(ctx, STATE_SYSCALL_ENTRY);
			/* do another step */
			cont_syscall_block(ctx);

			/* TODO: can signals interrupt a sigreturn? */
			assert(signal_pending(ctx->status) != SIGTRAP);

			/* orig_eax seems to be -1 here for
			 * not-understood reasons. */
			assert(ctx->event == -1);
			ctx->event = orig_event;
			record_event(ctx, STATE_SYSCALL_EXIT);
			ctx->switchable = 0;
			continue;
		} else if (ctx->event > 0) {
			/* We'll record the syscall-entry event
			 * below. */
			ctx->exec_state = EXEC_STATE_ENTRY_SYSCALL;
		} else if (ctx->event == SYS_restart_syscall) {
			/* Syscalls like nanosleep(), poll() which
			 * can't be restarted with their original
			 * arguments use the ERESTART_RESTARTBLOCK
			 * code.
			 *
			 * ---------------->
			 * Kernel will execute restart_syscall()
			 * instead, which changes arguments before
			 * restarting syscall.
			 * <----------------
			 *
			 * SA_RESTART is ignored (assumed not set)
			 * similarly to ERESTARTNOHAND. (Kernel can't
			 * honor SA_RESTART since restart data is
			 * saved in "restart block" in task struct,
			 * and if signal handler uses a syscall which
			 * in turn saves another such restart block,
			 * old data is lost and restart becomes
			 * impossible)
			 */
			debug("  restarting syscall %s",
				syscallname(ctx->last_syscall));
			/* From errno.h:
			 * These should never be seen by user
			 * programs.  To return one of ERESTART*
			 * codes, signal_pending() MUST be set.  Note
			 * that ptrace can observe these at syscall
			 * exit tracing, but they will never be left
			 * for the debugged user process to see. */
			ctx->exec_state = EXEC_STATE_ENTRY_SYSCALL;
			/* We do not record the syscall_restart event
			 * as it will not appear in the replay */
			continue;
		} else {
			fatal("Unhandled event %s (%d)",
			      strevent(ctx->event), ctx->event);
		}

		if (ctx->desched_rec) {
			/* Replay needs to be prepared to see the
			 * ioctl() that arms the desched counter when
			 * it's trying to step to the entry of
			 * |call|. */
			record_synthetic_event(ctx, USR_ARM_DESCHED);
		}

		record_event(ctx, STATE_SYSCALL_ENTRY);

		if (ctx->flushed_syscallbuf) {
			record_synthetic_event(ctx, USR_SYSCALLBUF_RESET);
			ctx->flushed_syscallbuf = 0;
		}
		if (ctx->desched_rec) {
			ctx->syscallbuf_hdr->abort_commit = 1;
			record_synthetic_event(ctx,
					       USR_SYSCALLBUF_ABORT_COMMIT);
		}
	} /* while loop */
}
