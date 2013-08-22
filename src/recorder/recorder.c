/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Recorder"

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

#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/syscall_buffer.h"
#include "../share/task.h"
#include "../share/trace.h"
#include "../share/util.h"

#define PTRACE_EVENT_NONE			0

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
	handle_signal(t);
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
		rec_process_syscall(t);
		record_event(t);

		/* issue an additional continue, since the process was stopped by the additional ptrace event */
		sys_ptrace_syscall(t->tid);
		sys_waitpid(t->tid, &t->status);
		status_changed(t);

		record_event(t);
		pop_syscall(t);

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
		sys_waitpid(new_tid, &t->status);
		rec_sched_register_thread(t->tid, new_tid, share_sighandlers);

		/* execute an additional ptrace_sysc((0xFF0000 & status) >> 16), since we setup trace like that.
		 * If the event is vfork we must no execute the cont_block, since the parent sleeps until the
		 * child has finished */
		if (event == PTRACE_EVENT_VFORK) {
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

	assert(!task_may_be_blocked(t));

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
	/* TODO: this is incorrect if the syscall isn't restarted
	 * right away, for example if a signal handler runs in the
	 * intervening time. */
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

/**
 * "Thaw" a frozen interrupted syscall if |t| is restarting it.
 * Return nonzero if a syscall is indeed restarted.
 *
 * If |t| is at the point where an interrupted syscall may or may not
 * be restarted, and the syscall isn't restarted, then that frozen
 * interrupted syscall is discarded.
 */
static int maybe_restart_syscall(struct task* t)
{
	const struct user_regs_struct* old_regs;

	if (SYS_restart_syscall == t->event) {
		/* This is a special case because SYS_restart_syscall
		 * *must* restart a syscall.  Otherwise we don't know
		 * which syscall's exit we're about to record. */
		assert_exec(t, (t->ev && EV_SYSCALL_INTERRUPTION == t->ev->type
				&& t->ev->syscall.is_restart
				/* TODO: this check is a training
				 * wheel for now, since the
				 * last_syscall is subsumed by the
				 * event stack.  Can remove when we're
				 * confident the event stack is
				 * working properly. */
				&& t->last_syscall == t->ev->syscall.no),
			    "Must have interrupted syscall to advance");

		t->ev->type = EV_SYSCALL;
		debug("  SYS_restart_syscall'ing %s",
		      syscallname(t->ev->syscall.no));
		return 0;
	}

	if (!t->ev || EV_SYSCALL_INTERRUPTION != t->ev->type) {
		return 0;
	}

	/* From here on, we must pop the interrupted syscall whether
	 * or not we restart it. */

	if (t->ev->syscall.no != t->event) {
		debug("  (interrupted syscall was %s, this is %s)",
		      syscallname(t->ev->syscall.no), syscallname(t->event));
		pop_syscall_interruption(t);
		return 0;
	}

	/* It's possible for the tracee to resume after a sighandler
	 * with a fresh syscall that happens to be the same as the one
	 * that was interrupted.  So we check here if the args are the
	 * same.
	 *
	 * Of course, it's possible (but less likely) for the tracee
	 * to incidentally resume with a fresh syscall that just
	 * happens to have the same *arguments* too.  But in that
	 * case, we would usually set up scratch buffers etc the same
	 * was as for the original interrupted syscall, so we just
	 * save a step here.
	 *
	 * TODO: it's possible for arg structures to be mutated
	 * between the original call and restarted call in such a way
	 * that it might change the scratch allocation decisions. */
	old_regs = &t->ev->syscall.regs;
	if (old_regs->ebx != t->regs.ebx
	    || old_regs->ecx != t->regs.ecx
	    || old_regs->edx != t->regs.edx
	    || old_regs->esi != t->regs.esi
	    || old_regs->edi != t->regs.edi
	    || old_regs->ebp != t->regs.ebp) {
		debug("  (args for interrupted %s are different than now)",
		      syscallname(t->ev->syscall.no));
		pop_syscall_interruption(t);
		return 0;
	}

	debug("  restarting %s", syscallname(t->ev->syscall.no));
	t->ev->type = EV_SYSCALL;
	return 1;
}

static void syscall_state_changed(struct task** tp, int by_waitpid)
{
	struct task* t = *tp;
	pid_t tid = t->tid;

	switch (t->ev->syscall.state) {
	case ENTERING_SYSCALL:
		debug_exec_state("EXEC_SYSCALL_ENTRY", t);

		if (!t->ev->syscall.is_restart) {
			/* Save a copy of the arg registers so that we
			 * can use them to detect later restarted
			 * syscalls, if this syscall ends up being
			 * restarted.  We have to save the registers
			 * in this rather awkward place because we
			 * need the original registers; the restart
			 * (if it's not a SYS_restart_syscall restart)
			 * will use the original registers. */
			memcpy(&t->ev->syscall.regs, &t->regs,
			       sizeof(t->ev->syscall.regs));
		}

		/* continue and execute the system call */
		t->switchable = rec_prepare_syscall(t);
		cont_nonblock(t);
		debug_exec_state("after cont", t);

		t->ev->syscall.state = PROCESSING_SYSCALL;
		return;

	case PROCESSING_SYSCALL:
		debug_exec_state("EXEC_IN_SYSCALL", t);

		assert(by_waitpid);
		/* Linux kicks tasks out of syscalls before delivering
		 * signals. */
		assert_exec(t, !signal_pending(t->status),
			    "Signal %s pending while %d in syscall???",
			    signalname(signal_pending(t->status)), t->tid);

		status_changed(t);
		t->ev->syscall.state = EXITING_SYSCALL;
		t->switchable = 0;
		return;

	case EXITING_SYSCALL: {
		int syscallno = t->ev->syscall.no;
		int retval;

		debug_exec_state("EXEC_SYSCALL_DONE", t);

		assert(signal_pending(t->status) == 0);
		assert(SYS_sigreturn != t->event);

		/* TODO: are there any other points where we need to
		 * handle ptrace events (other than the seccomp-bpf
		 * traps)? */
		handle_ptrace_event(tp);
		t = *tp;
		if (!t || t->event == SYS_vfork) {
			return;
		}

		read_child_registers(tid, &t->regs);
		t->event = t->regs.orig_eax;
		if (SYS_restart_syscall == t->event) {
			t->event = syscallno;
		}
		retval = t->regs.eax;

		assert_exec(t, (syscallno == t->event
				|| (SYS_rrcall_init_syscall_buffer == syscallno
				    && RRCALL_init_syscall_buffer == t->event)),
			    "Event stack and current event must be in sync.");
		assert_exec(t, (-ENOSYS != retval
				|| (0 > syscallno
				    || RRCALL_init_syscall_buffer == t->event
				    || SYS_clone == syscallno
				    || SYS_exit_group == syscallno
				    || SYS_exit == syscallno)),
			    "Exiting syscall %s, but retval is -ENOSYS, usually only seen at entry",
			    syscallname(syscallno));

		debug("  orig_eax:%ld (%s); eax:%ld",
		      t->regs.orig_eax, syscallname(syscallno), t->regs.eax);

		/* a syscall_restart ending is equivalent to the
		 * restarted syscall ending */
		if (t->ev->syscall.is_restart) {
			debug("  exiting restarted %s", syscallname(syscallno));
		}

		/* TODO: is there any reason a restart_syscall can't
		 * be interrupted by a signal and itself restarted? */
		t->will_restart = (syscallno != SYS_restart_syscall
				   && SYSCALL_WILL_RESTART(retval));
		/* no need to process the syscall in case its
		 * restarted this will be done in the exit from the
		 * restart_syscall */
		if (!t->will_restart) {
			rec_process_syscall(t);
		} else {
			debug("  will restart %s (from retval %d)",
			      syscallname(syscallno), retval);

			rec_prepare_restart_syscall(t);
			/* If we're going to restart this syscall,
			 * we've most likely fudged some of the
			 * argument registers with scratch pointers.
			 * We don't want to record those fudged
			 * registers, because scratch doesn't exist in
			 * replay.  So cover our tracks here. */
			copy_syscall_arg_regs(&t->regs, &t->ev->syscall.regs);
			write_child_registers(tid, &t->regs);

			/* TODO: this old code serves as training
			 * wheels for the event stack.  Remove when
			 * event stack is working well. */
			/* if the syscall is about to be restarted,
			 * save the last syscall performed by it. */
			t->last_syscall = syscallno;
		}
		record_event(t);

		/* If we're not going to restart this syscall, we're
		 * done with it.  But if we are, "freeze" it on the
		 * event stack until the execution point where it
		 * might be restarted. */
		if (!t->will_restart) {
			pop_syscall(t);
		} else {
			t->ev->type = EV_SYSCALL_INTERRUPTION;
			t->ev->syscall.is_restart = 1;
		}

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
		fatal("Unknown exec state %d", t->ev->syscall.state);
	}
}

/**
 * After a SYS_sigreturn "exit" of task |t| with return value |ret|,
 * check to see if there's an interrupted syscall that /won't/ be
 * restarted, and if so, pop it off the pending event stack.
 */
static void maybe_discard_syscall_interruption(struct task* t, int ret)
{
	int syscallno;

	if (!t->ev || EV_SYSCALL_INTERRUPTION != t->ev->type) {
		/* We currently don't track syscalls interrupted with
		 * ERESTARTSYS or ERESTARTNOHAND, so it's possible for
		 * a sigreturn not to affect the event stack. */
		debug("  (no interrupted syscall to retire)");
		return;
	}

	syscallno = t->ev->syscall.no;
	if (0 > ret) {
		/* The sigreturn won't restart the interrupted
		 * syscall.  Pop it. */
		debug("  not restarting interrupted %s",
		      syscallname(syscallno));
		pop_syscall_interruption(t);
	} else if (0 < ret) {
		assert_exec(t, syscallno == ret,
			    "Interrupted call was %s, and sigreturn claims to be restarting %s",
			    syscallname(syscallno), syscallname(ret));
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
		int ret;

		push_syscall(t, t->event);
		t->ev->syscall.state = ENTERING_SYSCALL;

		/* These system calls never return; we remain
		 * in the same execution state */
		/* we record the sigreturn event here, since we have
		 * to do another ptrace_cont to fully process the
		 * sigreturn system call. */
		debug("  sigreturn");
		/* Recording the sigreturn here may flush the
		 * syscallbuf.  That's OK: if the signal interrupted
		 * an in-progress buffered syscall, then we made sure
		 * we stepped the tracee to a happy place before
		 * delivering the signal, so the syscallbuf was locked
		 * on entry if it needed to be.  In that case, the
		 * sighandler wouldn't have used the syscallbuf.  And
		 * if the syscallbuf was unlocked, then that means the
		 * tracee didn't need to lock it, so it's OK for the
		 * sighandler to use it. */
		record_event(t);

		/* "Finish" the sigreturn. */
		sys_ptrace_syscall(t->tid);
		sys_waitpid(t->tid, &t->status);
		status_changed(t);
		ret = t->regs.eax;

		/* TODO: can signals interrupt a sigreturn? */
		assert(signal_pending(t->status) != SIGTRAP);

		/* orig_eax seems to be -1 here for not-understood
		 * reasons. */
		assert(t->event == -1);
		t->event = orig_event;
		t->ev->syscall.state = EXITING_SYSCALL;
		record_event(t);
		pop_syscall(t);

		/* We've finished processing this signal now. */
		pop_signal_handler(t);
		/* If the sigreturn isn't restarting an interrupted
		 * syscall we're tracking, go ahead and pop it. */
		maybe_discard_syscall_interruption(t, ret);

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

		if (!maybe_restart_syscall(t)) {
			push_syscall(t, t->event);
		}
		t->ev->syscall.state = ENTERING_SYSCALL;
		record_event(t);
	} else if (t->event == SYS_restart_syscall) {
		/* In this case, the call /must/ restart a syscall, or
		 * abort. */
		maybe_restart_syscall(t);

		t->ev->syscall.state = ENTERING_SYSCALL;
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

void record()
{
	struct task *t = NULL;

	while (rec_sched_get_num_threads() > 0) {
		int by_waitpid;

		t = rec_sched_get_active_thread(t, &by_waitpid);

		debug("Active task is %d", t->tid);

		if (t->scratch_ptr == NULL) {
			rec_init_scratch_memory(t);
		}

		assert(!by_waitpid || task_may_be_blocked(t));
		if (t->ev && EV_SYSCALL == t->ev->type) {
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
