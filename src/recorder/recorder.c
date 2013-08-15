/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#define _GNU_SOURCE

#include "recorder.h"

#include <assert.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <poll.h>
#include <sched.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "handle_signal.h"
#include "rec_process_event.h"
#include "rec_sched.h"

#include "../replayer/replayer.h" /* for emergency_debug() */
#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/syscall_buffer.h"
#include "../share/task.h"
#include "../share/trace.h"
#include "../share/util.h"

#define PTRACE_EVENT_NONE			0
static struct flags rr_flags_ = { 0 };
static bool filter_on_ = FALSE;

static void rec_init_scratch_memory(struct task *t)
{
	const int scratch_size = 512 * sysconf(_SC_PAGE_SIZE);
	/* initialize the scratchpad for blocking system calls */
	struct current_state_buffer state;

	prepare_remote_syscalls(t, &state);
	t->scratch_ptr = (void*)remote_syscall6(
		t, &state, SYS_mmap2,
		0, scratch_size,
		PROT_READ | PROT_WRITE | PROT_EXEC, /* EXEC, really? */
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	t->scratch_size = scratch_size;
	finish_remote_syscalls(t, &state);

	// record this mmap for the replay
	struct user_regs_struct orig_regs;
	read_child_registers(t->tid,&orig_regs);
	int eax = orig_regs.eax;
	orig_regs.eax = (uintptr_t)t->scratch_ptr;
	write_child_registers(t->tid,&orig_regs);
	struct mmapped_file file = {0};
	file.time = get_global_time();
	file.tid = t->tid;
	file.start = t->scratch_ptr;
	file.end = t->scratch_ptr + scratch_size;
	sprintf(file.filename,"scratch for thread %d",t->tid);
	record_mmapped_file_stats(&file);

	int event = t->event;
	t->event = USR_INIT_SCRATCH_MEM;
	push_pseudosig(t, EUSR_INIT_SCRATCH_MEM, HAS_EXEC_INFO);
	record_event(t);
	pop_pseudosig(t);
	t->event = event;

	orig_regs.eax = eax;
	write_child_registers(t->tid,&orig_regs);
}

static void status_changed(struct task* t)
{
	read_child_registers(t->tid, &t->regs);
	t->event = t->regs.orig_eax;
	if (t->event == RRCALL_init_syscall_buffer) {
		t->event = (-t->event | RRCALL_BIT);
	}
	handle_signal(&rr_flags_, t);
}

static void cont_nonblock(struct task *t)
{
	sys_ptrace_syscall(t->tid);
}

uintptr_t progress;

static void handle_ptrace_event(struct task** tp)
{
	struct task* t = *tp;

	/* handle events */
	int event = GET_PTRACE_EVENT(t->status);
	if (event != PTRACE_EVENT_NONE) {
		debug("  %d: handle_ptrace_event %d: syscall %s",
		      t->tid, event, syscallname(t->event));
	}
	switch (event) {

	case PTRACE_EVENT_NONE:
		break;

	case PTRACE_EVENT_VFORK_DONE:
		push_syscall(t, t->event);
		t->ev->syscall.state = EXITING_SYSCALL;
		rec_process_syscall(t, t->event, rr_flags_);
		record_event(t);

		/* issue an additional continue, since the process was stopped by the additional ptrace event */
		sys_ptrace_syscall(t->tid);
		sys_waitpid(t->tid, &t->status);
		status_changed(t);

		record_event(t);
		pop_syscall(t);

		t->exec_state = RUNNABLE;
		t->switchable = 1;
		break;

	case PTRACE_EVENT_CLONE:
	case PTRACE_EVENT_FORK:
	case PTRACE_EVENT_VFORK: {
		/* get new tid, register at the scheduler and setup HPC */
		int new_tid = sys_ptrace_getmsg(t->tid);
		int share_sighandlers;

		/* ensure that clone was successful */
		assert(read_child_eax(t->tid) != -1);

		read_child_registers(t->tid, &t->regs);
		/* The rather misleadingly named CLONE_SIGHAND flag
		 * actually means *share* the sighandler table.  (The
		 * flags param is argument 3, which is edx.)  fork and
		 * vfork must always copy sighandlers, there's no
		 * option to not copy. */
		share_sighandlers = (SYS_clone == t->regs.orig_eax) ?
				    (CLONE_SIGHAND & t->regs.edx) :
				    COPY_SIGHANDLERS;

		/* wait until the new thread is ready */
		sys_waitpid(new_tid, &(t->status));
		rec_sched_register_thread(&rr_flags_, t->tid, new_tid,
					  share_sighandlers);

		/* execute an additional ptrace_sysc((0xFF0000 & status) >> 16), since we setup trace like that.
		 * If the event is vfork we must no execute the cont_block, since the parent sleeps until the
		 * child has finished */
		if (event == PTRACE_EVENT_VFORK) {
			t->exec_state = PROCESSING_SYSCALL;
			t->switchable = 1;

			push_syscall(t, t->event);
			t->ev->syscall.state = ENTERING_SYSCALL;
			record_event(t);
			pop_syscall(t);

			cont_nonblock(t);
		} else {
			sys_ptrace_syscall(t->tid);
			sys_waitpid(t->tid, &t->status);
			status_changed(t);
		}
		break;
	}

	case PTRACE_EVENT_EXEC: {
		struct sighandlers* old_table = t->sighandlers;

		push_syscall(t, t->event);
		t->ev->syscall.state = ENTERING_SYSCALL;
		record_event(t);
		pop_syscall(t);

		sys_ptrace_syscall(t->tid);
		sys_waitpid(t->tid, &t->status);
		status_changed(t);

		rec_init_scratch_memory(t);
		t->sighandlers = sighandlers_copy(old_table);
		sighandlers_reset_user_handlers(t->sighandlers);
		sighandlers_unref(&old_table);
		assert(signal_pending(t->status) == 0);
		break;
	}

	case PTRACE_EVENT_EXIT:
		t->event = USR_EXIT;
		push_pseudosig(t, EUSR_EXIT, HAS_EXEC_INFO);
		record_event(t);
		pop_pseudosig(t);

		rec_sched_deregister_thread(tp);
		t = *tp;
		break;

	default:
		log_err("Unknown ptrace event: %x -- bailing out", event);
		sys_exit();
		break;
	}
}

#define debug_exec_state(_msg, _t)					\
	debug(_msg ": pevent=%d, event=%s",				\
	      GET_PTRACE_EVENT(_t->status), strevent(_t->event))

/**
 * Resume execution of |t| to the next notable event, such as a
 * syscall.  |t->event| may be mutated if a signal is caught.
 *
 * (Pass DEFAULT_CONT to the |force_syscall| parameter and ignore it;
 * it's an implementation detail.)
 */
enum { DEFAULT_CONT = 0, FORCE_SYSCALL = 1 };
static void resume_execution(struct task* t, int force_cont)
{
	int ptrace_event;

	assert(RUNNABLE == t->exec_state);

	debug_exec_state("EXEC_START", t);

	if (t->will_restart && filter_on_) {
		debug("  PTRACE_SYSCALL to restarted %s",
		      syscallname(t->last_syscall));
	}

	if (!filter_on_ || FORCE_SYSCALL == force_cont || t->will_restart) {
		/* We won't receive PTRACE_EVENT_SECCOMP events until
		 * the seccomp filter is installed by the
		 * syscall_buffer lib in the child, therefore we must
		 * record in the traditional way (with PTRACE_SYSCALL)
		 * until it is installed. */
		sys_ptrace_syscall(t->tid);
	} else {
		/* When the seccomp filter is on, instead of capturing
		 * syscalls by using PTRACE_SYSCALL, the filter will
		 * generate the ptrace events. This means we allow the
		 * process to run using PTRACE_CONT, and rely on the
		 * seccomp filter to generate the special
		 * PTRACE_EVENT_SECCOMP event once a syscall happens.
		 * This event is handled here by simply allowing the
		 * process to continue to the actual entry point of
		 * the syscall (using cont_syscall_block()) and then
		 * using the same logic as before. */
		sys_ptrace_cont(t->tid);
	}
	t->will_restart = 0;

	sys_waitpid(t->tid, &t->status);
	status_changed(t);

	debug_exec_state("  after resume", t);

	ptrace_event = GET_PTRACE_EVENT(t->status);
	if (PTRACE_EVENT_SECCOMP == ptrace_event
	    || PTRACE_EVENT_SECCOMP_OBSOLETE == ptrace_event) {
		filter_on_ = TRUE;
		/* See long comments above. */
		debug("  (skipping past seccomp-bpf trap)");
		return resume_execution(t, FORCE_SYSCALL);
	}
}

static void syscall_state_changed(struct task** tp, int by_waitpid)
{
	struct task* t = *tp;

	switch (t->exec_state) {
	case ENTERING_SYSCALL:
		debug_exec_state("EXEC_SYSCALL_ENTRY", t);

		/* continue and execute the system call */
		t->switchable = rec_prepare_syscall(t, t->event);
		cont_nonblock(t);

		debug_exec_state("after cont", t);

		t->exec_state = PROCESSING_SYSCALL;
		return;

	case PROCESSING_SYSCALL:
		debug_exec_state("EXEC_IN_SYSCALL", t);

		assert(t->exec_state = PROCESSING_SYSCALL);
		assert(by_waitpid);

		if (signal_pending(t->status)) {
			/* TODO: need state stack to properly handle
			 * signals, if they indeed are ever delivered
			 * in this state. */
			log_warn("Signal %s may not be handled correctly",
				 signalname(signal_pending(t->status)));
		}
		status_changed(t);
		t->exec_state = EXITING_SYSCALL;
		t->switchable = 0;
		return;

	case EXITING_SYSCALL: {
		struct user_regs_struct regs;
		int syscall, retval;

		debug_exec_state("EXEC_SYSCALL_DONE", t);

		assert(signal_pending(t->status) == 0);

		read_child_registers(t->tid,&regs);
		syscall = regs.orig_eax;
		retval = regs.eax;
		if (0 <= syscall
		    && SYS_clone != syscall
		    && SYS_exit_group != syscall && SYS_exit != syscall
		    && -ENOSYS == retval) {
			log_err("Exiting syscall %s, but retval is -ENOSYS, usually only seen at entry",
				syscallname(syscall));
			emergency_debug(t);
		}

		debug("  orig_eax:%d (%s); eax:%ld",
		      syscall, syscallname(syscall), regs.eax);

		/* we received a signal while in the system call and
		 * send it right away*/
		/* we have already sent the signal and process
		 * sigreturn */
		assert(t->event != SYS_sigreturn);

		/* if the syscall is about to be restarted, save the
		 * last syscall performed by it. */
		if (syscall != SYS_restart_syscall
		    && SYSCALL_WILL_RESTART(retval)) {
			debug("  retval %d, will restart %s",
			      retval, syscallname(syscall));
			t->last_syscall = syscall;
			t->will_restart = 1;
		}

		/* TODO: are there any other points where we need to
		 * handle ptrace events (other than the seccomp-bpf
		 * traps)? */
		handle_ptrace_event(tp);
		t = *tp;
		if (!t || t->event == SYS_vfork) {
			return;
		}

		assert(signal_pending(t->status) != SIGTRAP);
		/* a syscall_restart ending is equivalent to the
		 * restarted syscall ending */
		if (syscall == SYS_restart_syscall) {
			syscall = t->last_syscall;
			t->event = syscall;
			debug("  exiting restarted %s", syscallname(syscall));
		}

		t->ev->syscall.state = EXITING_SYSCALL;
		/* no need to process the syscall in case its
		 * restarted this will be done in the exit from the
		 * restart_syscall */
		if (!SYSCALL_WILL_RESTART(retval)) {
			rec_process_syscall(t, syscall, rr_flags_);
		}
		record_event(t);
		pop_syscall(t);

		t->exec_state = RUNNABLE;
		t->switchable = 1;
		if (t->desched_rec) {
			/* If this syscall was interrupted by a
			 * desched event, then just after the finished
			 * syscall there will be an ioctl() to disarm
			 * the event that we won't record here.  So
			 * save a breadcrumb so that replay knows to
			 * expect it and skip over it. */
			t->desched_rec = NULL;

			push_pseudosig(t, EUSR_DISARM_DESCHED, NO_EXEC_INFO);
			record_event(t);
			pop_pseudosig(t);

			/* We also need to ensure that the syscallbuf
			 * doesn't try to commit to the syscallbuf;
			 * we've already recorded the syscall. */
			t->syscallbuf_hdr->abort_commit = 1;
			push_pseudosig(t, EUSR_SYSCALLBUF_ABORT_COMMIT,
				       NO_EXEC_INFO);
			record_event(t);
			pop_pseudosig(t);
		}
		return;
	}

	default:
		fatal("Unknown exec state %d", t->exec_state);
	}
}

static void runnable_state_changed(struct task* t)
{
	/* Have to disable context-switching until we know it's safe
	 * to allow switching the context. */
	t->switchable = 0;

	if (t->event < 0) {
		/* We just saw a (pseudo-)signal.  handle_signal()
		 * took care of recording any events related to the
		 * (pseudo-)signal. */
		/* TODO: is there any reason not to enable switching
		 * after signals are delivered? */
		t->switchable = (t->event == SIG_SEGV_RDTSC
				   || t->event == USR_SCHED);
	} else if (t->event == SYS_sigreturn
		   || t->event == SYS_rt_sigreturn) {
		int orig_event = t->event;
		push_syscall(t, t->event);
		t->ev->syscall.state = ENTERING_SYSCALL;

		/* These system calls never return; we remain
		 * in the same execution state */
		/* we record the sigreturn event here, since we have
		 * to do another ptrace_cont to fully process the
		 * sigreturn system call. */
		debug("  sigreturn");
		record_event(t);
		assert(!t->flushed_syscallbuf);
		/* do another step */
		sys_ptrace_syscall(t->tid);
		sys_waitpid(t->tid, &t->status);
		status_changed(t);

		/* TODO: can signals interrupt a sigreturn? */
		assert(signal_pending(t->status) != SIGTRAP);

		/* orig_eax seems to be -1 here for not-understood
		 * reasons. */
		assert(t->event == -1);
		t->event = orig_event;
		t->ev->syscall.state = EXITING_SYSCALL;
		record_event(t);
		pop_syscall(t);

		t->switchable = 0;
	} else if (t->event > 0) {
		/* We just entered a syscall. */
		if (t->desched_rec) {
			/* Replay needs to be prepared to see the
			 * ioctl() that arms the desched counter when
			 * it's trying to step to the entry of
			 * |call|. */
			push_pseudosig(t, EUSR_ARM_DESCHED, NO_EXEC_INFO);
			record_event(t);
			pop_pseudosig(t);
		}

		push_syscall(t, t->event);
		t->ev->syscall.state = ENTERING_SYSCALL;
		record_event(t);

		t->exec_state = ENTERING_SYSCALL;
	} else if (t->event == SYS_restart_syscall) {
		/* Syscalls like nanosleep(), poll() which can't be
		 * restarted with their original arguments use the
		 * ERESTART_RESTARTBLOCK code.
		 *
		 * ---------------->
		 * Kernel will execute restart_syscall() instead,
		 * which changes arguments before restarting syscall.
		 * <----------------
		 *
		 * SA_RESTART is ignored (assumed not set) similarly
		 * to ERESTARTNOHAND. (Kernel can't honor SA_RESTART
		 * since restart data is saved in "restart block" in
		 * task struct, and if signal handler uses a syscall
		 * which in turn saves another such restart block, old
		 * data is lost and restart becomes impossible) */
		debug("  restarting syscall %s",
		      syscallname(t->last_syscall));
		/* From errno.h:
		 * These should never be seen by user programs.  To
		 * return one of ERESTART* codes, signal_pending()
		 * MUST be set.  Note that ptrace can observe these at
		 * syscall exit tracing, but they will never be left
		 * for the debugged user process to see. */
		t->exec_state = ENTERING_SYSCALL;
		assert(!t->flushed_syscallbuf);
	} else {
		fatal("Unhandled event %s (%d)",
		      strevent(t->event), t->event);
	}

	if (t->flushed_syscallbuf) {
		push_pseudosig(t, EUSR_SYSCALLBUF_RESET, NO_EXEC_INFO);
		record_event(t);
		t->flushed_syscallbuf = 0;
		pop_pseudosig(t);
	}
}

void record(const struct flags* rr_flags)
{
	rr_flags_ = *rr_flags;
	struct task *t = NULL;

	while (rec_sched_get_num_threads() > 0) {
		int by_waitpid;

		t = rec_sched_get_active_thread(&rr_flags_, t,
						  &by_waitpid);

		debug("Active task is %d", t->tid);

		if (t->scratch_ptr == NULL) {
			rec_init_scratch_memory(t);
		}

		assert(!by_waitpid || PROCESSING_SYSCALL == t->exec_state);
		if (t->exec_state > RUNNABLE) {
			syscall_state_changed(&t, by_waitpid);
			continue;
		}

		if (progress++ % 10000 == 0) {
			fprintf(stderr,".");
			fflush(stdout);
		}

		resume_execution(t, DEFAULT_CONT);
		runnable_state_changed(t);
	}
}
