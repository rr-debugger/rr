/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Signal"

#include "handle_signal.h"

#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/user.h>

#include "recorder.h"

#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/syscall_buffer.h"
#include "../share/task.h"
#include "../share/trace.h"
#include "../share/util.h"

static __inline__ unsigned long long rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}

/**
 * Return nonzero if |t| was stopped because of a SIGSEGV resulting
 * from a rdtsc and |t| was updated appropriately, zero otherwise.
 */
static int try_handle_rdtsc(struct task *t)
{
	int handled = 0;
	pid_t tid = t->tid;
	int sig = signal_pending(t->status);
	assert(sig != SIGTRAP);

	if (sig <= 0 || sig != SIGSEGV) {
		return 0;
	}

	int size;
	char *inst = get_inst(t, 0, &size);
	if (!inst) {
		/* If the segfault was caused by a jump to a bad $ip,
		 * then we obviously won't be able to read the
		 * instruction. */
		return 0;
	}

	/* if the current instruction is a rdtsc, the segfault was triggered by
	 * by reading the rdtsc instruction */
	if (strncmp(inst, "rdtsc", 5) == 0) {
		long int eax, edx;
		unsigned long long current_time;

		current_time = rdtsc();
		eax = current_time & 0xffffffff;
		edx = current_time >> 32;

		struct user_regs_struct regs;
		read_child_registers(tid, &regs);
		regs.eax = eax;
		regs.edx = edx;
		regs.eip += size;
		write_child_registers(tid, &regs);

		t->event = SIG_SEGV_RDTSC;
		push_pseudosig(t, ESIG_SEGV_RDTSC, HAS_EXEC_INFO);
		record_event(t);
		pop_pseudosig(t);

		handled = 1;

		debug("  trapped for rdtsc: returning %llu", current_time);
	}

	sys_free((void**)&inst);

	return handled;
}

static void disarm_desched_event(struct task* t)
{
	if (ioctl(t->desched_fd, PERF_EVENT_IOC_DISABLE, 0)) {
		fatal("Failed to disarm desched event");
	}
}

static uint64_t read_desched_counter(struct task* t)
{
	uint64_t nr_descheds;
	read(t->desched_fd, &nr_descheds, sizeof(nr_descheds));
	return nr_descheds;
}

static int advance_syscall_boundary(struct task* t,
				     struct user_regs_struct* regs)
{
	pid_t tid = t->tid;
	int status;

	sys_ptrace_syscall(tid);
	sys_waitpid(tid, &status);
	read_child_registers(tid, regs);
	if (!(WIFSTOPPED(status) && (STOPSIG_SYSCALL == WSTOPSIG(status)
				     /* TODO: non-desched SIGIO could
				      * happen here */
				     || SIGIO == WSTOPSIG(status)))) {
		/* TODO: need to handle signals here */
		fatal("Trying to reach syscall boundary, but saw signal %s instead (status 0x%x)",
		      signalname(WSTOPSIG(status)), status);
	}
	return WSTOPSIG(status);
}

/**
 * Return nonzero if |t| was stopped because of a SIGIO resulting
 * from notification of |t| being descheduled, zero otherwise.  The
 * tracee's execution may be advanced, and if so |regs| is updated to
 * the tracee's latest state.
 */
static int try_handle_desched_event(struct task* t, const siginfo_t* si,
				    struct user_regs_struct* regs)
{
	int call, sig;
	uint64_t nr_descheds;

	assert(SIGIO == si->si_signo);

	if (si->si_code != POLL_IN || si->si_fd != t->desched_fd_child) {
		debug("  (SIGIO not for desched: code=%d, fd=%d)",
		      si->si_code, si->si_fd);
		return 0;
	}

	/* TODO: how can signals interrupt us here? */

	/* The desched event just fired.  That implies that the
	 * arm-desched ioctl went into effect, and that the
	 * disarm-desched syscall didn't take effect.  Since a signal
	 * is pending for the tracee, then if the tracee was in a
	 * syscall, linux has exited it with an -ERESTART* error code.
	 * That means the tracee is about to (re-)enter either
	 *
	 *  1. buffered syscall
	 *  2. disarm-desched ioctl syscall
	 *
	 * We can figure out which one by simply issuing a
	 * ptrace(SYSCALL) and examining the tracee's registers.
	 *
	 * If the tracee enters the disarm-desched ioctl, it's going
	 * to commit a record of the buffered syscall to the
	 * syscallbuf, and we can safely send the tracee back on its
	 * way, ignoring the desched completely.
	 *
	 * If it enters the buffered syscall, then the desched event
	 * has served its purpose and we need to prepare the tracee to
	 * be context-switched.
	 *
	 * One implementation note is that when the tracer is
	 * descheduled in interval (C) above, we see *two* SIGIOs.
	 * The current theory of what's happening is
	 *
	 *  o child gets descheduled, bumps counter to i and schedules
	 *    SIGIO
	 *  o SIGIO notification "schedules" child, but it doesn't
	 *    actually run any application code
	 *  o child is being ptraced, so we "deschedule" child to
	 *    notify parent and bump counter to i+1.  (The parent
	 *    hasn't had a chance to clear the counter yet.)
	 *  o another counter signal is generated, but SIGIO is
	 *    already pending so this one is queued
	 *  o parent is notified and sees counter value i+1
	 *  o parent stops delivery of first signal and disarms
	 *    counter
	 *  o second SIGIO dequeued and delivered, notififying parent
	 *    (counter is disarmed now, so no pseudo-desched possible
	 *    here)
	 *  o parent notifiedand sees counter value i+1 again
	 *  o parent stops delivery of second SIGIO and we continue on
	 *
	 * So we "work around" this by the tracer expecting two SIGIO
	 * notifications, and silently discarding both.*/

	/* Clear the pending input. */
	nr_descheds = read_desched_counter(t);
	(void)nr_descheds;
	debug("  (desched #%llu during `%s')", nr_descheds, syscallname(call));

	/* Prevent further desched notifications from firing while
	 * we're advancing the tracee.  We're going to leave it in a
	 * consistent state anyway, so the event is no longer
	 * useful. */
	disarm_desched_event(t);

	/* Decline to deliver the SIGIO to the tracee, and eat the
	 * extraneous SIGIO. */
	sig = advance_syscall_boundary(t, regs);
	assert_exec(t, SIGIO == sig,
		    "Trying to skip redundant SIGIO after desched event, but got sig %s at $ip %p (untraced entry %p); desched? %s; syscall %s",
		    signalname(sig),
		    (void*)regs->eip, t->untraced_syscall_ip,
		    is_desched_event_syscall(t, regs) ? "yes" : "no",
		    syscallname(regs->orig_eax));

	/* Continue the tracee to its next syscall entry. */
	advance_syscall_boundary(t, regs);
	if (is_disarm_desched_event_syscall(t, regs)) {
		debug("  (at disarm-desched, so finished buffered syscall; resuming)");
		return USR_NOOP;
	}

	/* The tracee is (re-)entering the buffered syscall.  Stash
	 * away this breadcrumb so that we can figure out what syscall
	 * the tracee was in, and how much "scratch" space it carved
	 * off the syscallbuf, if needed. */
	t->desched_rec = next_record(t->syscallbuf_hdr);
	call = t->desched_rec->syscallno;

	debug("  resuming (and probably switching out) blocked `%s'",
	      syscallname(call));

	return call;
}

static int is_deterministic_signal(const siginfo_t* si)
{
	switch (si->si_signo) {
		/* These signals may be delivered deterministically;
		 * we'll check for sure below. */
	case SIGILL:
	case SIGTRAP:
	case SIGBUS:
	case SIGFPE:
	case SIGSEGV:
	case SIGSTKFLT:
		/* As bits/siginfo.h documents,
		 *
		 *   Values for `si_code'.  Positive values are
		 *   reserved for kernel-generated signals.
		 *
		 * So if the signal is maybe-synchronous, and the
		 * kernel delivered it, then it must have been
		 * delivered deterministically. */
		return si->si_code > 0;
	default:
		/* All other signals can never be delivered
		 * deterministically (to the approximation required by
		 * rr). */
		return 0;
	}

}

static void record_signal(int sig, struct task* t, const siginfo_t* si,
			  uint64_t max_rbc)
{
	int has_user_handler = sighandlers_has_user_handler(t->sighandlers,
							    sig);
	int resethand = sighandlers_is_resethand(t->sighandlers, sig);
	size_t sigframe_size = 0;

	if (sig == rr_flags()->ignore_sig) {
		log_info("Declining to deliver %s by user request",
			 signalname(sig));
		t->event = USR_NOOP;
		return;
	}

	push_pending_signal(t, sig, is_deterministic_signal(si));

	if (t->ev->signal.deterministic) {
		t->event = -(sig | DET_SIGNAL_BIT);
	} else {
		t->event = -sig;
	}

	/* This event is used by the replayer to advance to the point
	 * of signal delivery. */
	record_event(t);
	reset_hpc(t, max_rbc);

	t->ev->type = EV_SIGNAL_DELIVERY;
	if (has_user_handler) {
		debug("  %s has user handler", signalname(sig));
		/* Deliver the signal immediately when there's a user
		 * handler: we need to record the sigframe that the
		 * kernel sets up. */
		sys_ptrace_singlestep_sig(t->tid, sig);
		t->ev->signal.delivered = 1;

		sys_waitpid(t->tid, &t->status);
		/* It's been observed that when tasks enter
		 * sighandlers, the singlestep operation above doesn't
		 * retire any instructions; and indeed, if an
		 * instruction could be retired, this code wouldn't
		 * work.  This also cross-checks the sighandler
		 * information we maintain in |t->sighandlers|. */
		assert(0 == read_insts(t->hpc));

		/* TODO: find out actual struct sigframe size. 128
		 * seems to be too small. */
		sigframe_size = 1024;

		read_child_registers(t->tid, &t->regs);

		t->ev->type = EV_SIGNAL_HANDLER;
	} else {
		debug("  no user handler for %s", signalname(sig));
	}

	/* We record this data regardless to simplify replay. */
	record_child_data(t, sigframe_size, (void*)t->regs.esp);

	if (resethand) {
		sighandlers_set_disposition(t->sighandlers, sig,
					    SIG_DFL, NO_RESET);
	}

	/* This event is used by the replayer to set up the signal
	 * handler frame, or to record the resulting state of the
	 * stepi if there wasn't a signal handler. */
	record_event(t);

	/* We need to deliver the signal in the next continue
	 * request. */
	t->switchable = 0;
}

static int is_trace_trap(const siginfo_t* si)
{
	return SIGTRAP == si->si_signo && TRAP_TRACE == si->si_code;
}

/**
 * Return nonzero if |si| seems to indicate that single-stepping in
 * the syscallbuf lib reached a syscall entry.
 *
 * What we *really* want to do is check to see if the delivered signal
 * was |STOPSIG_SYSCALL|, like when we continue with PTRACE_SYSCALL.
 * But for some reason that's not delivered with PTRACE_SINGLESTEP.
 * What /does/ seem to be delivered is SIGTRAP/code=BRKPT, as opposed
 * to SIGTRAP/code=TRACE for stepping normal instructions.
 */
static int seems_to_be_syscallbuf_syscall_trap(const siginfo_t* si)
{
	return (STOPSIG_SYSCALL == si->si_signo
		|| (SIGTRAP == si->si_signo && TRAP_BRKPT == si->si_code));
}

/**
 * Take |t| to a place where it's OK to deliver a signal.  |si| and
 * |regs| must be the current state of |t|.  The registers at the
 * happy place will be returned in |regs|.
 */
void go_to_a_happy_place(struct task* t,
			 const siginfo_t* si, struct user_regs_struct* regs)
{
	pid_t tid = t->tid;
	/* If we deliver the signal at the tracee's current execution
	 * point, it will result in a syscall-buffer-flush event being
	 * recorded if there are any buffered syscalls.  The
	 * signal-delivery event will follow.  So the definition of a
	 * "happy place" to deliver a signal is one in which the
	 * syscall buffer flush (i.e., executing all the buffered
	 * syscalls) will be guaranteed to happen before the signal
	 * delivery during replay.
	 *
	 * If the syscallbuf isn't allocated, then there can't be any
	 * buffered syscalls, so there's no chance of a
	 * syscall-buffer-flush event being recorded before the signal
	 * delivery.  So that's a happy place.
	 *
	 * If the $ip isn't in the syscall lib and the syscallbuf is
	 * allocated, then we may have buffered syscalls.  But the $ip
	 * being outside the lib means one of two things: the tracee
	 * is either doing something unrelated to the syscall lib, or
	 * called a wrapper in the syscallbuf lib and the buffer
	 * overflowed (falling back on a traced syscall).  In either
	 * case, the buffer-flush event will do what we want, so it's
	 * a happy place.
	 *
	 * So we continue with the $ip in the syscallbuf lib and the
	 * syscallbuf allocated.  For the purpose of this analysis, we
	 * can abstract the tracee's execution state as being in one
	 * of these intervals
	 *
	 * --- ... ---
	 *
	 *   (Before we allocate the syscallbuf, it's OK to deliver
	 *   the signal, as discussed above.)
	 *
	 * --- allocated syscallbuf ---
	 *
	 *   In this interval, no syscalls can be buffered, so there's
	 *   no possibility of a syscall-buffer-flush event being
	 *   recorded before the signal delivery.
	 *
	 * --- check to see if syscallbuf is locked ---
	 *
	 *   Assume there are buffered syscalls.  If the check says
	 *   "buffer is locked" (meaning we're re-entering the
	 *   syscallbuf code through a signal handler), then we'll
	 *   record a buffer-flush event (or already have).  But, this
	 *   means that during replay, we'll have already finished
	 *   flushing the buffer at this point in execution.  So the
	 *   check will say, "buffer is *un*locked".  That will cause
	 *   replay divergence.  So,
	 *
	 *   ***** NOT SAFE TO DELIVER SIGNAL HERE *****
	 *
	 * --- lock syscallbuf ---
	 *
	 *   The lib locks the buffer just before it allocates a
	 *   record.  Assume that the buffer is almost full.  During
	 *   recording, the lib can allocate a record that overflows
	 *   the buffer.  The tracee will abort the untraced syscall
	 *   at |can_buffer_syscall()|.  But if we drop a buffer-flush
	 *   event here, then during replay the buffer will be clear
	 *   and the overflow check will (most likely) succeed.
	 *   (Technically, if this was the first record allocated,
	 *   it's OK.)  So
	 *
	 *   ***** NOT SAFE TO DELIVER SIGNAL HERE *****
	 *
	 * --- arm-desched ioctl() ---
	 *
	 *   If the buffer isn't empty during recording, and is
	 *   flushed just after this during replay, then the lib will
	 *   allocate a different pointer for the record.  This
	 *   diverges so
	 *
	 *   ***** NOT SAFE TO DELIVER SIGNAL HERE *****
	 *
	 * --- (untraced) syscall ---
	 *
	 *   Still not safe for the reason above.  Note, if the tracee
	 *   falls back on a traced syscall, then its $ip will be
	 *   outside the syscallbuf lib, and that's a happy place (see
	 *   above).
	 *
	 *   ***** NOT SAFE TO DELIVER SIGNAL HERE *****
	 *
	 * --- disarm-desched ioctl() ---
	 *
	 *   Still not safe for the reason above.
	 *
	 *   ***** NOT SAFE TO DELIVER SIGNAL HERE *****
	 *
	 * --- commit syscall record ---
	 *
	 *   We just exited all code related to the last syscall in
	 *   the buffer, so during replay all buffered syscalls must
	 *   have been retired by now.  So it's OK to deliver the
	 *   signal.
	 *
	 * --- unlock syscallbuf ---
	 *
	 *   Still safe for the reasons above.
	 *
	 * --- ... ---
	 *
	 * The reason the analysis is that pedantic is because our
	 * next job is to figure out which interval the tracee is in.
	 * We can observe the following state in the tracee
	 *  - $ip
	 *  - buffer locked-ness
	 *  - buffer record counter
	 *  - enter/exit syscall
	 *
	 * It's not hard to work out what state bits imply which
	 * interval, and how changes in that state signify moving to
	 * another interval, and that's what the code below does. */
	struct syscallbuf_hdr initial_hdr;
	struct syscallbuf_hdr* hdr = t->syscallbuf_hdr;
	int status = t->status;

	debug("Stepping tracee to happy place to deliver signal ...");

	if (!hdr) {
		/* Witness that we're in the (...,
		 * allocated-syscallbuf) interval. */
		debug("  tracee hasn't allocated syscallbuf yet");
		return;
	}

	if (SYSCALLBUF_IS_IP_IN_LIB(regs->eip, t)
	    && is_deterministic_signal(si)) {
		fatal("TODO: support deterministic signals triggered by syscallbuf code");
	}
	/* TODO: when we add support for deterministic signals, we
	 * should sigprocmask-off all tracee signals while we're
	 * stepping.  If we tried that with the current impl, the
	 * syscallbuf code segfaulting would lead to an infinite
	 * single-stepping loop here.. */

	initial_hdr = *hdr;
	while (1) {
		siginfo_t tmp_si;
		int is_syscall;

		if (!SYSCALLBUF_IS_IP_IN_LIB(regs->eip, t)) {
			/* The tracee can't possible affect the
			 * syscallbuf here, so a flush is safe.. */
			debug("  tracee outside syscallbuf lib");
			goto happy_place;
		}
		if (initial_hdr.locked && !hdr->locked) {
			/* Witness that the tracee moved into the safe
			 * (unlock-syscallbuf, ...)  interval. */
			debug("  tracee just unlocked syscallbuf");
			goto happy_place;
		}
		/* XXX we /could/ check if the syscall record was just
		 * commited, since that's a safe interval, but the
		 * tracee will also unlock the buffer just after that,
		 * so meh.  Should do this though if it's a perf
		 * win. */

		/* We've now established that the tracee is in the
		 * interval (allocated-syscallbuf, unlock-syscallbuf).
		 * Until we can prove the tracee moved into a safe
		 * interval within that, keep stepping. */
		sys_ptrace_singlestep(tid);
		sys_waitpid(tid, &status);

		assert(WIFSTOPPED(status));
		sys_ptrace_getsiginfo(tid, &tmp_si);
		read_child_registers(tid, regs);
		is_syscall = seems_to_be_syscallbuf_syscall_trap(&tmp_si);

		if (!is_syscall && !is_trace_trap(&tmp_si)) {
			fatal("TODO: support multiple pending signals; received %s (code: %d) at $ip:%p while trying to deliver %s (code: %d)",
			      signalname(tmp_si.si_signo), tmp_si.si_code,
			      (void*)regs->eip,
			      signalname(si->si_signo), si->si_code);
		}
		if (!is_syscall) {
			continue;
		}

		/* TODO more signals can be delivered while we're
		 * stepping here too.  Sigh.  See comment above about
		 * masking signals off.  When we mask off signals, we
		 * won't need to disarm the desched event, but we will
		 * need to handle spurious desched notifications. */
		if (is_desched_event_syscall(t, regs)) {
			debug("  stepping over desched-event syscall");
			/* Finish the syscall. */
			sys_ptrace_singlestep(tid);
			sys_waitpid(tid, &status);
			if (is_arm_desched_event_syscall(t, regs)) {
				/* Disarm the event: we don't need or
				 * want to hear about descheds while
				 * we're stepping the tracee through
				 * the syscall wrapper. */
				disarm_desched_event(t);
			}
			/* We don't care about disarm-desched-event
			 * syscalls; they're irrelevant. */
		} else {
			debug("  running wrapped syscall");
			/* We may have been notified of the signal
			 * just after arming the event, but just
			 * before entering the syscall.  So disarm for
			 * safety. */
			/* XXX we really should warn about this, but
			 * it's just too noisy during unit tests.
			 * Should find a better way to choose mode. */
			/*log_warn("Disabling context-switching for possibly-blocking syscall (%s); deadlock may follow",
			  syscallname(regs->orig_eax));*/
			disarm_desched_event(t);
			/* And (hopefully!) finish the syscall. */
			sys_ptrace_singlestep(tid);
			sys_waitpid(tid, &status);
		}
	}

happy_place:
	/* TODO: restore previous tracee signal mask. */
	(void)0;
}

void handle_signal(struct task* t)
{
	pid_t tid = t->tid;
	int sig = signal_pending(t->status);
	int event;
	siginfo_t si;
	struct user_regs_struct regs;
	uint64_t max_rbc = rr_flags()->max_rbc;

	if (sig <= 0) {
		return;
	}

	debug("%d: handling signal %s (pevent: %d, event: %s)",
	      t->tid, signalname(sig),
	      GET_PTRACE_EVENT(t->status), strevent(t->event));

	sys_ptrace_getsiginfo(tid, &si);
	read_child_registers(tid, &regs);

	/* We have to check for a desched event first, because for
	 * those we *do not* want to (and cannot, most of the time)
	 * step the tracee out of the syscallbuf code before
	 * attempting to deliver the signal. */
	if (SIGIO == sig
	    && (event = try_handle_desched_event(t, &si, &regs))) {
		t->event = event;
		return;
	}

	go_to_a_happy_place(t, &si, &regs);

	/* See if this signal occurred because of an rr implementation detail,
	 * and fudge t appropriately. */
	switch (sig) {
	case SIGSEGV:
		if (try_handle_rdtsc(t)) {
			return;
		}
		break;

	case SIGIO:
		/* TODO: imprecise counters can probably race with
		 * delivery of a "real" SIGIO */
		if (read_rbc(t->hpc) >= max_rbc) {
			/* HPC interrupt due to exceeding time
			 * slice. */
			t->event = USR_SCHED;
			push_pseudosig(t, EUSR_SCHED, HAS_EXEC_INFO);
			/* TODO: only record the SCHED event if it
			 * actually results in a context switch, since
			 * this will flush the syscallbuf and can
			 * cause replay to be pathologically slow in
			 * certain cases. */
			record_event(t);
			pop_pseudosig(t);
			return;
		}
		break;
	}

	/* This signal was generated by the program or an external
	 * source, record it normally. */
	record_signal(sig, t, &si, max_rbc);
}
