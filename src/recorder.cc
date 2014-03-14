/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Recorder"

#include "recorder.h"

#include <assert.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <poll.h>
#include <sched.h>
#include <string.h>
#include <sys/epoll.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "preload/syscall_buffer.h"

#include "dbg.h"
#include "hpc.h"
#include "record_signal.h"
#include "record_syscall.h"
#include "recorder_sched.h"
#include "task.h"
#include "trace.h"
#include "util.h"

/* Nonzero when it's safe to deliver signals, namely, when the initial
 * tracee has exec()'d the tracee image.  Before then, the address
 * space layout will not be the same during replay as recording, so
 * replay won't be able to find the right execution point to deliver
 * the signal. */
static int can_deliver_signals;

static void status_changed(Task* t)
{
	t->event = t->regs().orig_eax;
	/* If the initial tracee isn't prepared to handle signals yet,
	 * then us ignoring the ptrace notification here will have the
	 * side effect of declining to deliver the signal. */
	if (can_deliver_signals) {
		handle_signal(t);
	}
}

static void handle_ptrace_event(Task** tp)
{
	Task* t = *tp;

	/* handle events */
	int event = t->ptrace_event();
	if (event != PTRACE_EVENT_NONE) {
		debug("  %d: handle_ptrace_event %d: event %s",
		      t->tid, event, strevent(t->event));
	}
	switch (event) {

	case PTRACE_EVENT_NONE:
		break;

	case PTRACE_EVENT_CLONE:
	case PTRACE_EVENT_FORK: {
		int new_tid = t->get_ptrace_eventmsg();
		void* stack = (void*)t->regs().ecx;
		void* ctid = (void*)t->regs().edi;
		// fork and can never share these resources, only
		// copy, so the flags here aren't meaningful for it.
		int flags_arg = (SYS_clone == t->regs().orig_eax) ?
				t->regs().ebx : 0;
		Task* new_task = t->clone(clone_flags_to_task_flags(flags_arg),
					  stack, ctid, new_tid);
		// Wait until the new task is ready.
		new_task->wait();

		start_hpc(new_task, rr_flags()->max_rbc);

		t->cont_syscall();
		status_changed(t);
		break;
	}

	case PTRACE_EVENT_EXEC: {
		/* The initial tracee, if it's still around, is now
		 * for sure not running in the initial rr address
		 * space, so we can unblock signals. */
		can_deliver_signals = 1;

		push_syscall(t, t->event);
		t->ev->syscall.state = ENTERING_SYSCALL;
		record_event(t);
		pop_syscall(t);

		t->cont_syscall();
		status_changed(t);

		assert(t->pending_sig() == 0);
		break;
	}

	case PTRACE_EVENT_EXIT:
		if (EV_SYSCALL == t->ev->type
		    && SYS_exit_group == t->ev->syscall.no
		    && t->task_group()->task_set().size() > 1) {
			log_warn("exit_group() with > 1 task; may misrecord CLONE_CHILD_CLEARTID memory race");
			t->destabilize_task_group();
		}

		t->event = t->unstable ? USR_UNSTABLE_EXIT : USR_EXIT;
		push_pseudosig(t,
			       t->unstable ? EUSR_UNSTABLE_EXIT : EUSR_EXIT,
			       HAS_EXEC_INFO);
		record_event(t);
		pop_pseudosig(t);

		rec_sched_deregister_thread(tp);
		t = *tp;
		break;

	case PTRACE_EVENT_VFORK:
	case PTRACE_EVENT_VFORK_DONE:
	default:
		fatal("Unhandled ptrace event %s(%d)",
		      ptrace_event_name(event), event);
		break;
	}
}

#define debug_exec_state(_msg, _t)					\
	debug(_msg ": status=0x%x pevent=%d, event=%s",			\
	      (_t)->status(), (_t)->ptrace_event(), strevent(_t->event))

enum { DEFAULT_CONT = 0, FORCE_SYSCALL = 1 };
static void task_continue(Task* t, int force_cont, int sig)
{
	bool may_restart = t->at_may_restart_syscall();

	if (sig) {
		debug("  delivering %s to %d", signalname(sig), t->tid);
	}
	if (may_restart && t->seccomp_bpf_enabled) {
		debug("  PTRACE_SYSCALL to possibly-restarted %s",
		      syscallname(t->ev->syscall.no));
	}

	if (!t->seccomp_bpf_enabled
	    || FORCE_SYSCALL == force_cont || may_restart) {
		/* We won't receive PTRACE_EVENT_SECCOMP events until
		 * the seccomp filter is installed by the
		 * syscall_buffer lib in the child, therefore we must
		 * record in the traditional way (with PTRACE_SYSCALL)
		 * until it is installed. */
		t->cont_syscall_nonblocking(sig);
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
		t->cont_nonblocking(sig);
	}
}

/**
 * Resume execution of |t| to the next notable event, such as a
 * syscall.  |t->event| may be mutated if a signal is caught.
 *
 * (Pass DEFAULT_CONT to the |force_syscall| parameter and ignore it;
 * it's an implementation detail.)
 */
static bool resume_execution(Task* t, int force_cont)
{
	assert(!t->may_be_blocked());

	debug_exec_state("EXEC_START", t);

	task_continue(t, force_cont, /*no sig*/0);
	if (!t->wait()) {
		debug("  waitpid() interrupted");
		return false;
	}
	status_changed(t);

	debug_exec_state("  after resume", t);

	if (t->is_ptrace_seccomp_event()) {
		t->seccomp_bpf_enabled = true;
		/* See long comments above. */
		debug("  (skipping past seccomp-bpf trap)");
		return resume_execution(t, FORCE_SYSCALL);
	}
	return true;
}

/**
 * Step |t| forward utnil the desched event is disarmed.  If a signal
 * becomes pending in the interim, the |waitpid()| status is returned,
 * and |si| is filled in.  This allows the caller to deliver the
 * signal after this returns and the desched event is disabled.
 */
static int disarm_desched(Task* t, siginfo_t* si)
{
	int sig_status = 0;

	debug("desched: DISARMING_DESCHED_EVENT");
	/* TODO: send this through main loop. */
	/* TODO: mask off signals and avoid this loop. */
	do {
		t->cont_syscall();
		/* We can safely ignore SIG_TIMESLICE while trying to
		 * reach the disarm-desched ioctl: once we reach it,
		 * the desched'd syscall will be "done" and the tracee
		 * will be at a preemption point.  In fact, we *want*
		 * to ignore this signal.  Syscalls like read() can
		 * have large buffers passed to them, and we have to
		 * copy-out the buffered out data to the user's
		 * buffer.  This happens in the interval where we're
		 * reaching the disarm-desched ioctl, so that code is
		 * susceptible to receiving SIG_TIMESLICE.  If it
		 * does, we'll try to stepi the tracee to a safe point
		 * ... through a practically unbounded memcpy(), which
		 * can be very expensive. */
		int sig = t->pending_sig();
		if (HPC_TIME_SLICE_SIGNAL == sig) {
			continue;
		}

		t->event = t->regs().orig_eax;

		if (sig) {
			int old_sig =
				Task::pending_sig_from_status(sig_status);
			debug("  %s now pending", signalname(sig));
			assert_exec(t,
				    !sig_status || old_sig == sig,
				    "TODO multiple pending signals: %s became pending while %s already was",
				    signalname(sig),
				    signalname(old_sig));
			sig_status = t->status();
			t->get_siginfo(si);
		}
	} while (!t->is_disarm_desched_event_syscall());
	return sig_status;
}

/**
 * |t| is at a desched event and some relevant aspect of its state
 * changed.  (For now, changes except the original desched'd syscall
 * being restarted.)
 */
static void desched_state_changed(Task* t)
{
	switch (t->ev->desched.state) {
	case IN_SYSCALL:
		debug("desched: IN_SYSCALL");
		/* We need to ensure that the syscallbuf code doesn't
		 * try to commit the current record; we've already
		 * recorded that syscall.  The following event sets
		 * the abort-commit bit. */
		push_pseudosig(t, EUSR_SYSCALLBUF_ABORT_COMMIT, NO_EXEC_INFO);
		t->syscallbuf_hdr->abort_commit = 1;
		record_event(t);
		pop_pseudosig(t);

		t->ev->desched.state = DISARMING_DESCHED_EVENT;
		/* fall through */
	case DISARMING_DESCHED_EVENT: {
		siginfo_t si;
		int sig_status = disarm_desched(t, &si);

		t->ev->desched.state = DISARMED_DESCHED_EVENT;
		record_event(t);
		pop_desched(t);

		/* The tracee has just finished sanity-checking the
		 * aborted record, and won't touch the syscallbuf
		 * during this (aborted) transaction again.  So now is
		 * a good time for us to reset the record counter. */
		push_pseudosig(t, EUSR_SYSCALLBUF_RESET, NO_EXEC_INFO);
		t->syscallbuf_hdr->num_rec_bytes = 0;
		t->delay_syscallbuf_reset = 0;
		t->delay_syscallbuf_flush = 0;
		record_event(t);
		pop_pseudosig(t);

		if (sig_status) {
			debug("  delivering deferred %s",
			      signalname(t->pending_sig()));
			t->force_status(sig_status);
			handle_signal(t, &si);
		}
		return;
	}
	default:
		fatal("Unhandled desched state");
	}
}

static void syscall_not_restarted(Task* t)
{
	debug("  %d: popping abandoned interrupted %s; pending events:",
	      t->tid, syscallname(t->ev->syscall.no));
#ifdef DEBUGTAG
	log_pending_events(t);
#endif
	pop_syscall_interruption(t);

	push_pseudosig(t, EUSR_INTERRUPTED_SYSCALL_NOT_RESTARTED, NO_EXEC_INFO);
	record_event(t);
	pop_pseudosig(t);
}

/**
 * "Thaw" a frozen interrupted syscall if |t| is restarting it.
 * Return nonzero if a syscall is indeed restarted.
 *
 * A postcondition of this function is that |t->ev| is no longer a
 * syscall interruption, whether or whether not a syscall was
 * restarted.
 */
static int maybe_restart_syscall(Task* t)
{
	if (SYS_restart_syscall == t->event) {
		debug("  %d: SYS_restart_syscall'ing %s",
		      t->tid, syscallname(t->ev->syscall.no));
	}
	if (t->is_syscall_restart()) {
		t->ev->type = EV_SYSCALL;
		return 1;
	}
	if (EV_SYSCALL_INTERRUPTION == t->ev->type) {
		syscall_not_restarted(t);
	}
	return 0;
}

static void syscall_state_changed(Task* t, int by_waitpid)
{
	switch (t->ev->syscall.state) {
	case ENTERING_SYSCALL: {
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
			t->ev->syscall.regs = t->regs();
		}

		void* sync_addr = nullptr;
		uint32_t sync_val;
		t->switchable = rec_prepare_syscall(t, &sync_addr, &sync_val);

		// Resume the syscall execution in the kernel context.
		t->cont_syscall_nonblocking();
		debug_exec_state("after cont", t);

		if (sync_addr) {
			t->futex_wait(sync_addr, sync_val);
		}
		t->ev->syscall.state = PROCESSING_SYSCALL;
		return;
	}
	case PROCESSING_SYSCALL:
		debug_exec_state("EXEC_IN_SYSCALL", t);

		assert(by_waitpid);
		/* Linux kicks tasks out of syscalls before delivering
		 * signals. */
		assert_exec(t, !t->pending_sig(),
			    "Signal %s pending while %d in syscall???",
			    signalname(t->pending_sig()), t->tid);

		status_changed(t);
		t->ev->syscall.state = EXITING_SYSCALL;
		t->switchable = 0;
		return;

	case EXITING_SYSCALL: {
		int syscallno = t->ev->syscall.no;
		int may_restart;
		int retval;

		debug_exec_state("EXEC_SYSCALL_DONE", t);

		assert(t->pending_sig() == 0);
		assert(SYS_sigreturn != t->event);

		t->event = t->regs().orig_eax;
		if (SYS_restart_syscall == t->event) {
			t->event = syscallno;
		}
		retval = t->regs().eax;

		assert_exec(t, syscallno == t->event,
			    "Event stack and current event must be in sync.");
		assert_exec(t, (-ENOSYS != retval
				|| (0 > syscallno
				    || SYS_rrcall_init_buffers == t->event
				    || SYS_rrcall_monkeypatch_vdso == t->event
				    || SYS_clone == syscallno
				    || SYS_exit_group == syscallno
				    || SYS_exit == syscallno)),
			    "Exiting syscall %s, but retval is -ENOSYS, usually only seen at entry",
			    syscallname(syscallno));

		debug("  orig_eax:%ld (%s); eax:%ld",
		      t->regs().orig_eax, syscallname(syscallno),
		      t->regs().eax);

		/* a syscall_restart ending is equivalent to the
		 * restarted syscall ending */
		if (t->ev->syscall.is_restart) {
			debug("  exiting restarted %s", syscallname(syscallno));
		}

		/* TODO: is there any reason a restart_syscall can't
		 * be interrupted by a signal and itself restarted? */
		may_restart = (syscallno != SYS_restart_syscall
			       // SYS_pause is either interrupted or
			       // never returns.  It doesn't restart.
			       && syscallno != SYS_pause
			       && SYSCALL_MAY_RESTART(retval));
		/* no need to process the syscall in case its
		 * restarted this will be done in the exit from the
		 * restart_syscall */
		if (!may_restart) {
			rec_process_syscall(t);
			if (rr_flags()->check_cached_mmaps) {
				t->vm()->verify(t);
			}
		} else {
			debug("  may restart %s (from retval %d)",
			      syscallname(syscallno), retval);

			rec_prepare_restart_syscall(t);
			/* If we may restart this syscall, we've most
			 * likely fudged some of the argument
			 * registers with scratch pointers.  We don't
			 * want to record those fudged registers,
			 * because scratch doesn't exist in replay.
			 * So cover our tracks here. */
			struct user_regs_struct r = t->regs();
			copy_syscall_arg_regs(&r, &t->ev->syscall.regs);
			t->set_regs(r);
		}
		record_event(t);

		/* If we're not going to restart this syscall, we're
		 * done with it.  But if we are, "freeze" it on the
		 * event stack until the execution point where it
		 * might be restarted. */
		if (!may_restart) {
			pop_syscall(t);
			if (EV_DESCHED == t->ev->type) {
				debug("  exiting desched critical section");
				desched_state_changed(t);
			}
		} else {
			t->ev->type = EV_SYSCALL_INTERRUPTION;
			t->ev->syscall.is_restart = 1;
		}

		t->switchable = 1;
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
static void maybe_discard_syscall_interruption(Task* t, int ret)
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
		syscall_not_restarted(t);
	} else if (0 < ret) {
		assert_exec(t, syscallno == ret,
			    "Interrupted call was %s, and sigreturn claims to be restarting %s",
			    syscallname(syscallno), syscallname(ret));
	}
}

/**
 * If the syscallbuf has just been flushed, and resetting hasn't been
 * overridden with a delay request, then record the reset event for
 * replay.
 */
static void maybe_reset_syscallbuf(Task* t)
{
	if (t->flushed_syscallbuf && !t->delay_syscallbuf_reset) {
		push_pseudosig(t, EUSR_SYSCALLBUF_RESET, NO_EXEC_INFO);
		record_event(t);
		pop_pseudosig(t);
	}
	/* Any code that sets |delay_syscallbuf_reset| is responsible
	 * for recording its own SYSCALLBUF_RESET event at a
	 * convenient time. */
	t->flushed_syscallbuf = 0;
}

/** If the rbc seems to be working return, otherwise don't return. */
static void check_rbc(Task* t)
{
	if (can_deliver_signals || SYS_write != t->event) {
		return;
	}
	int fd = t->regs().ebx;
	assert_exec(t, -1 == fd,
		    "rbc write should have been to fd -1, instead was %d", fd);

	int64_t rbc = read_rbc(t->hpc);
	debug("rbc on entry to dummy write: %lld", rbc);
	if (!(rbc > 0)) {
		fprintf(stderr,
"\n"
"rr: internal recorder error:\n"
"  Retired-branch counter doesn't seem to be working.  Are you perhaps\n"
"  running rr in a VM but didn't enable perf-counter virtualization?\n");
		exit(EX_UNAVAILABLE);
	}
}

static void runnable_state_changed(Task* t)
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
		maybe_reset_syscallbuf(t);

		/* "Finish" the sigreturn. */
		t->cont_syscall();
		status_changed(t);
		ret = t->regs().eax;

		/* TODO: can signals interrupt a sigreturn? */
		assert(t->pending_sig() != SIGTRAP);

		/* orig_eax seems to be -1 here for not-understood
		 * reasons. */
		assert(t->event == -1);
		t->event = orig_event;
		t->ev->syscall.state = EXITING_SYSCALL;
		record_event(t);
		pop_syscall(t);

		/* We've finished processing this signal now. */
		pop_signal_handler(t);
		push_pseudosig(t, EUSR_EXIT_SIGHANDLER, NO_EXEC_INFO);
		record_event(t);
		pop_pseudosig(t);

		/* If the sigreturn isn't restarting an interrupted
		 * syscall we're tracking, go ahead and pop it. */
		maybe_discard_syscall_interruption(t, ret);

		t->switchable = 0;
	} else if (t->event >= 0) {
		/* We just entered a syscall. */
		check_rbc(t);
		if (!maybe_restart_syscall(t)) {
			push_syscall(t, t->event);
			rec_before_record_syscall_entry(t, t->ev->syscall.no);
		}
		assert_exec(t, EV_SYSCALL == t->ev->type,
			    "Should be at syscall event.");
		t->ev->syscall.state = ENTERING_SYSCALL;
		record_event(t);
	} else {
		fatal("Unhandled event %s (%d)",
		      strevent(t->event), t->event);
	}

	maybe_reset_syscallbuf(t);
}

/**
 * |t| is delivering a signal, and its state changed.  |by_waitpid| is
 * nonzero if the status change was observed by a waitpid() call.
 *
 * Delivering the signal to |t| may cause scheduling invariants about
 * the status of *other* threads to become temporarily invalid.  In
 * this case, this function returns nonzero.
 */
static int signal_state_changed(Task* t, int by_waitpid)
{
	assert(EV_SIGNAL_DELIVERY == t->ev->type);

	if (!t->ev->signal.delivered) {
		int sig = t->ev->signal.no;

		task_continue(t, DEFAULT_CONT, sig);
		t->ev->signal.delivered = 1;
		return t->switchable = possibly_destabilizing_signal(t, sig);
	}

	/* The tracee's waitpid status has changed, so we're finished
	 * delivering the signal. */
	pop_signal_delivery(t);

	status_changed(t);

	if (t->is_ptrace_seccomp_event()) {
		t->seccomp_bpf_enabled = true;
		/* See long comments above. */
		debug("  (skipping past seccomp-bpf trap)");
		resume_execution(t, FORCE_SYSCALL);
	}

	runnable_state_changed(t);
	return 0;
}

static bool term_request;

/**
 * A terminating signal was received.  Set the |term_request| bit to
 * terminate the trace at the next convenient point.
 *
 * If there's already a term request pending, then assume rr is wedged
 * and abort().
 */
static void handle_termsig(int sig)
{
	if (term_request) {
		fatal("Received termsig while an earlier one was pending.  We're probably wedged.");
	}
	log_info("Received termsig %s, requesting shutdown ...\n",
		 signalname(sig));
	term_request = true;
}

static void install_termsig_handlers(void)
{
	int termsigs[] = { SIGINT, SIGTERM };
	for (size_t i = 0; i < ALEN(termsigs); ++i) {
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = handle_termsig;
		sigaction(termsigs[i], &sa, NULL);
	}
}

/** If |term_request| is set, then terminate_recording(). */
static void maybe_process_term_request(Task* t)
{
	if (term_request) {
		terminate_recording(t);
	}
}

void record()
{
	Task *t = nullptr;

	install_termsig_handlers();

	while (Task::count() > 0) {
		int by_waitpid;

		maybe_process_term_request(t);

		Task* next = rec_sched_get_active_thread(t, &by_waitpid);
		if (!next) {
			maybe_process_term_request(t);
		}
		t = next;

		debug("line %d: Active task is %d. Events:",
		      get_global_time(), t->tid);
#ifdef DEBUGTAG
		log_pending_events(t);
#endif
		int ptrace_event = t->ptrace_event();
		assert_exec(t, (!by_waitpid || t->may_be_blocked() ||
				ptrace_event),
			    "%d unexpectedly runnable (0x%x) by waitpid",
			    t->tid, t->status());
		if (ptrace_event && !t->is_ptrace_seccomp_event()) {
			handle_ptrace_event(&t);
			if (!t) {
				continue;
			}
		}
		switch (t->ev->type) {
		case EV_DESCHED:
			desched_state_changed(t);
			continue;
		case EV_SYSCALL:
			syscall_state_changed(t, by_waitpid);
			continue;
		case EV_SIGNAL_DELIVERY: {
			int unstable = signal_state_changed(t, by_waitpid);
			if (unstable) {
				log_warn("Delivered core-dumping signal; may misrecord CLONE_CHILD_CLEARTID memory race");
				t->destabilize_task_group();
			}
			continue;
		}
		default:
			/* No special handling needed; continue on
			 * below. */
			break;
		}

		if (!resume_execution(t, DEFAULT_CONT)) {
			maybe_process_term_request(t);
		}
		runnable_state_changed(t);
	}
}

void terminate_recording(Task* t)
{
	log_info("Processing termination request ...");
	log_info("  recording final TRACE_TERMINATION event ...");
	record_trace_termination_event(t);
	flush_trace_files();

	// TODO: Task::killall() here?

	log_info("  exiting, goodbye.");
	exit(0);
}
