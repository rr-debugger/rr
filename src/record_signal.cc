/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Signal"

#include "record_signal.h"

#include <assert.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <x86intrin.h>

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "PerfCounters.h"
#include "RecordSession.h"
#include "task.h"
#include "TraceStream.h"
#include "util.h"

using namespace rr;
using namespace std;

static void handle_siginfo(Task* t, siginfo_t* si);

static __inline__ unsigned long long rdtsc(void) { return __rdtsc(); }

static const int STOPSIG_SYSCALL = 0x80 | SIGTRAP;

/**
 * Doesn't return if |si| wasn't triggered by a time-slice interrupt.
 */
static void assert_is_time_slice_interrupt(Task* t, const siginfo_t* si) {
  /* This implementation will of course fall over if rr tries to
   * record itself.
   *
   * NB: we can't check that the ticks is >= the programmed
   * target, because this signal may have become pending before
   * we reset the HPC counters.  There be a way to handle that
   * more elegantly, but bridge will be crossed in due time. */
  ASSERT(t, (PerfCounters::TIME_SLICE_SIGNAL == si->si_signo &&
             si->si_fd == t->hpc.ticks_fd() && POLL_IN == si->si_code))
      << "Tracee is using SIGSTKFLT??? (code=" << si->si_code
      << ", fd=" << si->si_fd << ")";
}

template <typename Arch> static size_t sigaction_sigset_size_arch() {
  return Arch::sigaction_sigset_size;
}

static size_t sigaction_sigset_size(SupportedArch arch) {
  RR_ARCH_FUNCTION(sigaction_sigset_size_arch, arch);
}

/**
 * Restore the blocked-ness and sigaction for SIGSEGV from |t|'s local
 * copy.
 */
static void restore_sigsegv_state(Task* t) {
  const vector<uint8_t>& sa = t->signal_action(SIGSEGV);
  AutoRemoteSyscalls remote(t);
  {
    AutoRestoreMem child_sa(remote, sa.data(), sa.size());
    int ret = remote.syscall(syscall_number_for_rt_sigaction(remote.arch()),
                             SIGSEGV, child_sa.get().as_int(), nullptr,
                             sigaction_sigset_size(remote.arch()));
    ASSERT(t, 0 == ret) << "Failed to restore SIGSEGV handler";
  }
  // NB: we would normally want to restore the SIG_BLOCK for
  // SIGSEGV here, but doing so doesn't change the kernel's
  // "SigBlk" mask.  There's no bug observed in the kernel's
  // delivery of SIGSEGV after the RDTSC trap, so we do nothing
  // here and move on.
}

/** Return true iff |t->ip()| points at a RDTSC instruction. */
static const uint8_t rdtsc_insn[] = { 0x0f, 0x31 };
static bool is_ip_rdtsc(Task* t) {
  uint8_t insn[sizeof(rdtsc_insn)];
  if (sizeof(insn) != t->read_bytes_fallible(t->ip(), sizeof(insn), insn)) {
    return false;
  }
  return !memcmp(insn, rdtsc_insn, sizeof(insn));
}

/**
 * Return true if |t| was stopped because of a SIGSEGV resulting
 * from a rdtsc and |t| was updated appropriately, false otherwise.
 */
static bool try_handle_rdtsc(Task* t, siginfo_t* si) {
  int sig = si->si_signo;
  assert(sig != SIGTRAP);

  if (sig != SIGSEGV || !is_ip_rdtsc(t)) {
    return false;
  }

  unsigned long long current_time = rdtsc();
  Registers r = t->regs();
  r.set_rdtsc_output(current_time);
  r.set_ip(r.ip() + sizeof(rdtsc_insn));
  t->set_regs(r);

  // When SIGSEGV is blocked, apparently the kernel has to do
  // some ninjutsu to raise the RDTSC trap.  We see the SIGSEGV
  // bit in the "SigBlk" mask in /proc/status cleared, and if
  // there's a user handler the SIGSEGV bit in "SigCgt" is
  // cleared too.  That's perfectly fine, except that it's
  // unclear who's supposed to undo the signal-state munging.  A
  // legitimate argument can be made that the tracer is
  // responsible, so we go ahead and restore the old state.
  //
  // One could also argue that this is a kernel bug.  If so,
  // then this is a workaround that can be removed in the
  // future.
  //
  // If we don't restore the old state, at least firefox has
  // been observed to hang at delivery of SIGSEGV.  However, the
  // test written for this bug, fault_in_code_addr, doesn't hang
  // without the restore.
  if (t->is_sig_blocked(SIGSEGV)) {
    restore_sigsegv_state(t);
  }

  t->push_event(Event(EV_SEGV_RDTSC, HAS_EXEC_INFO, t->arch()));
  LOG(debug) << "  trapped for rdtsc: returning " << current_time;
  return true;
}

static void arm_desched_event(Task* t) {
  if (ioctl(t->desched_fd, PERF_EVENT_IOC_ENABLE, 0)) {
    FATAL() << "Failed to arm desched event";
  }
}

static void disarm_desched_event(Task* t) {
  if (ioctl(t->desched_fd, PERF_EVENT_IOC_DISABLE, 0)) {
    FATAL() << "Failed to disarm desched event";
  }
}

/**
 * Return the event needing to be processed after this desched of |t|.
 * The tracee's execution may be advanced, and if so |regs| is updated
 * to the tracee's latest state.
 */
static void handle_desched_event(Task* t, const siginfo_t* si) {
  ASSERT(t, (SYSCALLBUF_DESCHED_SIGNAL == si->si_signo &&
             si->si_code == POLL_IN && si->si_fd == t->desched_fd_child))
      << "Tracee is using SIGSYS??? (code=" << si->si_code
      << ", fd=" << si->si_fd << ")";

  /* If the tracee isn't in the critical section where a desched
   * event is relevant, we can ignore it.  See the long comments
   * in syscall_buffer.c.
   *
   * It's OK if the tracee is in the critical section for a
   * may-block syscall B, but this signal was delivered by an
   * event programmed by a previous may-block syscall A. */
  if (!t->syscallbuf_hdr->desched_signal_may_be_relevant) {
    LOG(debug) << "  (not entering may-block syscall; resuming)";
    /* We have to disarm the event just in case the tracee
     * has cleared the relevancy flag, but not yet
     * disarmed the event itself. */
    disarm_desched_event(t);
    t->push_event(Event::noop(t->arch()));
    return;
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
   * An annoyance of the desched signal is that when the tracer
   * is descheduled in interval (C) above, we see normally (see
   * below) see *two* signals.  The current theory of what's
   * happening is
   *
   *  o child gets descheduled, bumps counter to i and schedules
   *    signal
   *  o signal notification "schedules" child, but it doesn't
   *    actually run any application code
   *  o child is being ptraced, so we "deschedule" child to
   *    notify parent and bump counter to i+1.  (The parent
   *    hasn't had a chance to clear the counter yet.)
   *  o another counter signal is generated, but signal is
   *    already pending so this one is queued
   *  o parent is notified and sees counter value i+1
   *  o parent stops delivery of first signal and disarms
   *    counter
   *  o second signal dequeued and delivered, notififying parent
   *    (counter is disarmed now, so no pseudo-desched possible
   *    here)
   *  o parent notifiedand sees counter value i+1 again
   *  o parent stops delivery of second signal and we continue on
   *
   * So we "work around" this by the tracer expecting two signal
   * notifications, and silently discarding both.
   *
   * One really fun edge case is that sometimes the desched
   * signal will interrupt the arm-desched syscall itself.
   * Continuing to the next syscall boundary seems to restart
   * the arm-desched syscall, and advancing to the boundary
   * again exits it and we start receiving desched signals
   * again.
   *
   * That may be a kernel bug, but we handle it by just
   * continuing until we we continue past the arm-desched
   * syscall *and* stop seeing signals. */
  while (true) {
    // Prevent further desched notifications from firing
    // while we're advancing the tracee.  We're going to
    // leave it in a consistent state anyway, so the event
    // is no longer useful.  We have to do this in each
    // loop iteration because a restarted arm-desched
    // syscall may have re-armed the event.
    disarm_desched_event(t);

    t->cont_syscall();
    int sig = t->stop_sig();

    if (STOPSIG_SYSCALL == sig) {
      if (t->is_arm_desched_event_syscall()) {
        continue;
      }
      break;
    }
    // Completely ignore spurious desched signals and
    // signals that aren't going to be delivered to the
    // tracee.
    //
    // Also ignore time-slice signals.  If the tracee ends
    // up at the disarm-desched ioctl, we'll reschedule it
    // with the ticks interrupt still programmed.  At worst,
    // the tracee will get an extra time-slice out of
    // this, on average, so we don't worry too much about
    // it.
    //
    // TODO: it's theoretically possible for this to
    // happen an unbounded number of consecutive times
    // and the tracee never switched out.
    if (SYSCALLBUF_DESCHED_SIGNAL == sig ||
        PerfCounters::TIME_SLICE_SIGNAL == sig || t->is_sig_ignored(sig)) {
      LOG(debug) << "  dropping ignored " << signal_name(sig);
      continue;
    }

    LOG(debug) << "  stashing " << signal_name(sig);
    t->stash_sig();
  }

  if (t->is_disarm_desched_event_syscall()) {
    LOG(debug)
        << "  (at disarm-desched, so finished buffered syscall; resuming)";
    t->push_event(Event::noop(t->arch()));
    return;
  }

  /* This prevents the syscallbuf record counter from being
   * reset until we've finished guiding the tracee through this
   * interrupted call.  We use the record counter for
   * assertions. */
  t->delay_syscallbuf_reset = true;

  /* The tracee is (re-)entering the buffered syscall.  Stash
   * away this breadcrumb so that we can figure out what syscall
   * the tracee was in, and how much "scratch" space it carved
   * off the syscallbuf, if needed. */
  const struct syscallbuf_record* desched_rec = next_record(t->syscallbuf_hdr);
  t->push_event(DeschedEvent(desched_rec, t->arch()));
  int call = t->desched_rec()->syscallno;
  /* Replay needs to be prepared to see the ioctl() that arms
   * the desched counter when it's trying to step to the entry
   * of |call|.  We'll record the syscall entry when the main
   * recorder code sees the tracee's syscall event. */
  t->record_current_event();

  /* Because we set the |delay_syscallbuf_reset| flag and the
   * record counter will stay intact for a bit, we need to also
   * prevent later events from flushing the syscallbuf until
   * we've unblocked the reset. */
  t->delay_syscallbuf_flush = true;

  /* The descheduled syscall was interrupted by a signal, like
   * all other may-restart syscalls, with the exception that
   * this one has already been restarted (which we'll detect
   * back in the main loop). */
  t->push_event(Event(interrupted, SyscallEvent(call, t->arch())));
  SyscallEvent& ev = t->ev().Syscall();
  ev.desched_rec = desched_rec;
  ev.regs = t->regs();
  /* For some syscalls (at least poll) but not all (at least not read),
   * repeated cont_syscall()s above of the same interrupted syscall
   * can set $orig_eax to 0 ... for unclear reasons. Fix that up here
   * otherwise we'll get a divergence during replay, which will not
   * encounter this problem.
   */
  ev.regs.set_original_syscallno(call);
  t->set_regs(ev.regs);
  ev.state = EXITING_SYSCALL;

  LOG(debug) << "  resuming (and probably switching out) blocked `"
             << t->syscall_name(call) << "'";
}

static SignalDeterministic is_deterministic_signal(const siginfo_t* si) {
  switch (si->si_signo) {
    /* These signals may be delivered deterministically;
     * we'll check for sure below. */
    case SIGILL:
    case SIGTRAP:
    case SIGBUS:
    case SIGFPE:
    case SIGSEGV:
      /* As bits/siginfo.h documents,
       *
       *   Values for `si_code'.  Positive values are
       *   reserved for kernel-generated signals.
       *
       * So if the signal is maybe-synchronous, and the
       * kernel delivered it, then it must have been
       * delivered deterministically. */
      return si->si_code > 0 ? DETERMINISTIC_SIG : NONDETERMINISTIC_SIG;
    default:
      /* All other signals can never be delivered
       * deterministically (to the approximation required by
       * rr). */
      return NONDETERMINISTIC_SIG;
  }
}

static void record_signal(Task* t, const siginfo_t* si) {
  // goto_a_happy_place's stepping can lead to the kernel forgetting
  // the siginfo for the signal we're going to deliver. Restore that
  // siginfo now.
  t->set_siginfo(*si);

  int sig = si->si_signo;
  if (sig == t->record_session().get_ignore_sig()) {
    LOG(info) << "Declining to deliver " << signal_name(sig)
              << " by user request";
    t->push_event(Event::noop(t->arch()));
    return;
  }

  t->push_event(SignalEvent(sig, is_deterministic_signal(si), t->arch()));
}

static bool is_trace_trap(const siginfo_t* si) {
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
static bool seems_to_be_syscallbuf_syscall_trap(const siginfo_t* si) {
  return (STOPSIG_SYSCALL == si->si_signo ||
          (SIGTRAP == si->si_signo && TRAP_BRKPT == si->si_code));
}

/**
 * Take |t| to a place where it's OK to deliver a signal.  |si| must
 * be the current state of |t|.  Return COMPLETE if stepping completed
 * successfully, or INCOMPLETE if it was interrupted by another signal.
 */
static Completion go_to_a_happy_place(Task* t, siginfo_t* si) {
  /* If we deliver the signal at the tracee's current execution
   * point, it will result in a syscall-buffer-flush event being
   * recorded if there are any buffered syscalls.  The
   * signal-delivery event will follow.  So the definition of a
   * "happy place" to deliver a signal is one in which the
   * syscall buffer flush (i.e., executing all the buffered
   * syscalls) will be guaranteed to happen before the signal
   * delivery during replay.
   *
   * Naively delivering the signal (and thereby flushing the
   * buffer) can cause the syscallbuf code to be reentered while
   * it's in the middle of processing a syscall, and that would
   * cause all sorts of things to go haywire, both during
   * recording and replay.  That's why the
   * |syscallbuf_hdr.locked| field exists: it establishes a
   * critical section of syscallbuf code that cannot be
   * reentered.  So those critical sections are not happy
   * places.
   *
   * By definition, anywhere outside those critical sections is
   * a happy place.  That includes the interval while the
   * syscallbuf isn't enabled.
   *
   * The only exception is descheduled syscalls.  They're an
   * exception because rr is already forced to bend over
   * backwards to abort their commits to the syscallbuf and
   * otherwise handle the desched signal interrupting the
   * syscall.  Note, the syscallbuf will stay locked while any
   * code invoked by the signal runs, so there are no reentrancy
   * problems.
   *
   * The code below determines if the tracee is in a happy place
   * per above, and if not, steps it until it finds one. */
  struct syscallbuf_hdr initial_hdr;
  struct syscallbuf_hdr* hdr = t->syscallbuf_hdr;
  bool desched_event_maybe_armed = true;

  LOG(debug) << "Stepping tracee to happy place to deliver signal ...";

  if (!hdr) {
    /* Can't be in critical section because the lock
     * doesn't exist yet! */
    LOG(debug) << "  tracee hasn't allocated syscallbuf yet";
    goto happy_place;
  }

  ASSERT(t, !(t->is_in_syscallbuf() &&
              is_deterministic_signal(si) == DETERMINISTIC_SIG))
      << "TODO: " << signal_name(si->si_signo) << " (code:" << si->si_code
      << ") raised by syscallbuf code";
  /* TODO: when we add support for deterministic signals, we
   * should sigprocmask-off all tracee signals while we're
   * stepping.  If we tried that with the current impl, the
   * syscallbuf code segfaulting would lead to an infinite
   * single-stepping loop here.. */

  initial_hdr = *hdr;
  while (true) {
    if (!t->is_in_syscallbuf()) {
      /* The tracee is outside the syscallbuf code,
       * so in most cases can't possibly affect
       * syscallbuf critical sections.  The
       * exception is signal handlers "re-entering"
       * desched'd syscalls, which are OK per
       * above.. */
      LOG(debug) << "  tracee outside syscallbuf lib";
      goto happy_place;
    }
    if (t->is_entering_traced_syscall()) {
      // Unlike the untraced syscall entry, if we
      // step a tracee into a *traced* syscall,
      // we'll see a SIGTRAP for the tracee.  That
      // causes several problems for rr, most
      // relevant of them to this code being that
      // the syscall entry looks like a synchronous
      // SIGTRAP generated from the syscallbuf lib,
      // which we don't know how to handle.
      LOG(debug) << "  tracee entering traced syscallbuf syscall";
      goto happy_place;
    }
    if (t->is_in_traced_syscall()) {
      LOG(debug) << "  tracee at traced syscallbuf syscall";
      goto happy_place;
    }
    if (t->is_in_untraced_syscall() && t->desched_rec()) {
      LOG(debug) << "  tracee interrupted by desched of "
                 << t->syscall_name(t->desched_rec()->syscallno);
      goto happy_place;
    }
    if (initial_hdr.locked && !hdr->locked) {
      /* Tracee just stepped out of a critical
       * section and into a happy place.. */
      LOG(debug) << "  tracee just unlocked syscallbuf";
      goto happy_place;
    }

    bool should_arm_desched_event = t->is_in_untraced_syscall();
    if (desched_event_maybe_armed != should_arm_desched_event) {
      if (should_arm_desched_event) {
        arm_desched_event(t);
      } else {
        disarm_desched_event(t);
      }
      desched_event_maybe_armed = should_arm_desched_event;
    }

    /* Move the tracee closer to a happy place.  NB: an
     * invariant of the syscallbuf is that all untraced
     * syscalls must be made from within a transaction
     * (critical section), so there's no chance here of
     * "skipping over" a syscall we should have
     * recorded. */
    LOG(debug) << "  stepi out of syscallbuf from " << t->ip();
    t->cont_singlestep();
    assert(t->stopped());

    siginfo_t tmp_si = t->get_siginfo();
    bool is_syscall = seems_to_be_syscallbuf_syscall_trap(&tmp_si);

    if (!is_syscall && !is_trace_trap(&tmp_si)) {
      if (PerfCounters::TIME_SLICE_SIGNAL == tmp_si.si_signo) {
        LOG(debug) << "  discarding HPC_TIME_SLICE_SIGNAL";
        continue;
      }
      if (SYSCALLBUF_DESCHED_SIGNAL == tmp_si.si_signo) {
        if (!t->is_in_untraced_syscall()) {
          // The performance counter is disarmed but
          // maybe this signal could already be pending.
          // We can ignore this signal.
          LOG(debug) << "  discarding SYSCALLBUF_DESCHED_SIGNAL";
          continue;
        }
        // TODO what if we get a signal just before
        // entering an untraced syscall, we step into
        // that syscall, and then it blocks? We'll
        // reach this point, but what should we do?
        // We can probably treat this as a happy_place
        // and just deliver our original signal, but
        // we'll need logic similar to handle_desched_event.
      }
      // In a desperate effort to avoid dying, discard
      // an ignored signal. This will preserve tracee
      // behavior. It means such signals won't be observed
      // in a debugger, but that will hardly ever be
      // important.
      if (PerfCounters::TIME_SLICE_SIGNAL == si->si_signo ||
          t->is_sig_ignored(si->si_signo)) {
        *si = tmp_si;
        LOG(debug) << "  upgraded delivery of HPC_TIME_SLICE_SIGNAL to "
                   << signal_name(si->si_signo);
        handle_siginfo(t, si);
        return INCOMPLETE;
      }
      // In another desperate effort to avoid dying, discard
      // the new signal if it's ignored.
      if (t->is_sig_ignored(tmp_si.si_signo)) {
        LOG(debug) << "  discarding ignored signal " << tmp_si.si_signo;
        continue;
      }

      ASSERT(t, false) << "TODO: support multiple pending signals; received "
                       << signal_name(tmp_si.si_signo)
                       << " (code: " << tmp_si.si_code << ") at $ip:" << t->ip()
                       << " while trying to deliver "
                       << signal_name(si->si_signo) << " (code: " << si->si_code
                       << ")";
    }
    if (!is_syscall) {
      continue;
    }

    LOG(debug) << "  running wrapped syscall";
    /* Finish the syscall. */
    t->cont_singlestep();
  }

happy_place:
  /* TODO: restore previous tracee signal mask. */
  return COMPLETE;
}

static void handle_siginfo(Task* t, siginfo_t* si) {
  LOG(debug) << t->tid << ": handling signal " << signal_name(si->si_signo)
             << " (pevent: " << t->ptrace_event() << ", event: " << t->ev();

  t->set_siginfo_for_synthetic_SIGCHLD(si);

  /* We have to check for a desched event first, because for
   * those we *do not* want to (and cannot, most of the time)
   * step the tracee out of the syscallbuf code before
   * attempting to deliver the signal. */
  if (SYSCALLBUF_DESCHED_SIGNAL == si->si_signo) {
    handle_desched_event(t, si);
    return;
  }

  if (go_to_a_happy_place(t, si) == INCOMPLETE) {
    /* While stepping, another signal arrived that we
     * "upgraded" to. */
    return;
  }

  /* See if this signal occurred because of an rr implementation detail,
   * and fudge t appropriately. */
  switch (si->si_signo) {
    case SIGSEGV:
      if (try_handle_rdtsc(t, si)) {
        return;
      }
      break;

    case PerfCounters::TIME_SLICE_SIGNAL:
      assert_is_time_slice_interrupt(t, si);

      t->push_event(Event(EV_SCHED, HAS_EXEC_INFO, t->arch()));
      return;
  }

  /* This signal was generated by the program or an external
   * source, record it normally. */

  if (t->emulate_ptrace_stop((si->si_signo << 8) | 0x7f,
                             SIGNAL_DELIVERY_STOP)) {
    // ptracer has been notified, so don't deliver the signal now.
    // The signal won't be delivered for real until the ptracer calls
    // PTRACE_CONT with the signal number (which we don't support yet!).
    t->push_event(Event::noop(t->arch()));
    return;
  }

  record_signal(t, si);
}

void handle_signal(Task* t) {
  assert(t->has_stashed_sig());

  siginfo_t si = t->pop_stash_sig();
  handle_siginfo(t, &si);
}
