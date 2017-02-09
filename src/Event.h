/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_EVENT_H_
#define RR_EVENT_H_

#include <assert.h>

#include <ostream>
#include <stack>
#include <string>

#include "Registers.h"
#include "kernel_abi.h"

struct syscallbuf_record;

namespace rr {

/**
 * During recording, sometimes we need to ensure that an iteration of
 * RecordSession::record_step schedules the same task as in the previous
 * iteration. The PREVENT_SWITCH value indicates that this is required.
 * For example, the futex operation FUTEX_WAKE_OP modifies userspace
 * memory; those changes are only recorded after the system call completes;
 * and they must be replayed before we allow a context switch to a woken-up
 * task (because the kernel guarantees those effects are seen by woken-up
 * tasks).
 * Entering a potentially blocking system call must use ALLOW_SWITCH, or
 * we risk deadlock. Most non-blocking system calls could use PREVENT_SWITCH
 * or ALLOW_SWITCH; for simplicity we use ALLOW_SWITCH to indicate a call could
 * block and PREVENT_SWITCH otherwise.
 * Note that even if a system call uses PREVENT_SWITCH, as soon as we've
 * recorded the completion of the system call, we can switch to another task.
 */
enum Switchable { PREVENT_SWITCH, ALLOW_SWITCH };

/**
 * Events serve two purposes: tracking Task state during recording, and
 * being stored in traces to guide replay. Some events are only used during
 * recording and are never actually stored in traces (and are thus irrelevant
 * to replay).
 */
enum EventType {
  EV_UNASSIGNED,
  EV_SENTINEL,
  // TODO: this is actually a pseudo-pseudosignal: it will never
  // appear in a trace, but is only used to communicate between
  // different parts of the recorder code that should be
  // refactored to not have to do that.
  EV_NOOP,
  EV_DESCHED,
  EV_SECCOMP_TRAP,

  // Events present in traces:

  // No associated data.
  EV_EXIT,
  // Tracee exited its sighandler.  We leave this breadcrumb so
  // that the popping of not-restarted syscall interruptions and
  // sigreturns is replayed in the same order.
  EV_EXIT_SIGHANDLER,
  // Pretty self-explanatory: recording detected that an
  // interrupted syscall wasn't restarted, so the interruption
  // record can be popped off the tracee's event stack.
  EV_INTERRUPTED_SYSCALL_NOT_RESTARTED,
  // Scheduling signal interrupted the trace.
  EV_SCHED,
  EV_SEGV_RDTSC,
  // Recorded syscallbuf data for one or more buffered syscalls.
  EV_SYSCALLBUF_FLUSH,
  EV_SYSCALLBUF_ABORT_COMMIT,
  // The syscallbuf was reset to the empty state. We record this event
  // later than it really happens, because during replay we must proceed to
  // the event *after* a syscallbuf flush and then reset the syscallbuf,
  // to ensure we don't reset it while preload code is still using the data.
  EV_SYSCALLBUF_RESET,
  // Syscall was entered, the syscall instruction was patched, and the
  // syscall was aborted. Resume execution at the patch.
  EV_PATCH_SYSCALL,
  // Map memory pages due to a (future) memory access. This is associated
  // with a mmap entry for the new pages.
  EV_GROW_MAP,
  // The trace was terminated before all tasks exited, most
  // likely because the recorder was sent a terminating signal.
  // There are no more trace frames coming, so the best thing to
  // do is probably to shut down.
  EV_TRACE_TERMINATION,
  // Like USR_EXIT, but recorded when the task is in an
  // "unstable" state in which we're not sure we can
  // synchronously wait for it to "really finish".
  EV_UNSTABLE_EXIT,
  // Use .signal.
  EV_SIGNAL,
  EV_SIGNAL_DELIVERY,
  EV_SIGNAL_HANDLER,
  // Use .syscall.
  EV_SYSCALL,
  EV_SYSCALL_INTERRUPTION,

  EV_LAST
};

enum HasExecInfo { NO_EXEC_INFO, HAS_EXEC_INFO };

/**
 * An encoding of the relevant bits of |struct event| that can be
 * cheaply and easily serialized.
 */
union EncodedEvent {
  struct {
    EventType type : 5;
    HasExecInfo has_exec_info : 1;
    SupportedArch arch_ : 1;
    int data : 25;
  };
  int encoded;

  bool operator==(const EncodedEvent& other) const {
    return encoded == other.encoded;
  }
  bool operator!=(const EncodedEvent& other) const { return !(*this == other); }

  SupportedArch arch() const { return arch_; }
};

static_assert(sizeof(int) == sizeof(EncodedEvent), "Bit fields are messed up");
static_assert(EV_LAST < (1 << 5), "Allocate more bits to the |type| field");

/**
 * Events are interesting occurrences during tracee execution which
 * are relevant for replay.  Most events correspond to tracee
 * execution, but some (a subset of "pseudosigs") save actions that
 * the *recorder* took on behalf of the tracee.
 */
struct BaseEvent {
  /**
   * Pass |HAS_EXEC_INFO| if the event is at a stable execution
   * point that we'll reach during replay too.
   */
  BaseEvent(HasExecInfo has_exec_info, SupportedArch arch)
      : has_exec_info(has_exec_info), arch_(arch) {}

  SupportedArch arch() const { return arch_; }

  // When replaying an event is expected to leave the tracee in
  // the same execution state as during replay, the event has
  // meaningful execution info, and it should be recorded for
  // checking.  But some pseudosigs aren't recorded in the same
  // tracee state they'll be replayed, so the tracee exeuction
  // state isn't meaningful.
  HasExecInfo has_exec_info;
  SupportedArch arch_;
};

/**
 * Desched events track the fact that a tracee's desched-event
 * notification fired during a may-block buffered syscall, which rr
 * interprets as the syscall actually blocking (for a potentially
 * unbounded amount of time).  After the syscall exits, rr advances
 * the tracee to where the desched is "disarmed" by the tracee.
 */
struct DeschedEvent : public BaseEvent {
  /** Desched of |rec|. */
  DeschedEvent(remote_ptr<const struct syscallbuf_record> rec,
               SupportedArch arch)
      : BaseEvent(NO_EXEC_INFO, arch), rec(rec) {}
  // Record of the syscall that was interrupted by a desched
  // notification.  It's legal to reference this memory /while
  // the desched is being processed only/, because |t| is in the
  // middle of a desched, which means it's successfully
  // allocated (but not yet committed) this syscall record.
  remote_ptr<const struct syscallbuf_record> rec;
};

enum SignalDeterministic { NONDETERMINISTIC_SIG = 0, DETERMINISTIC_SIG = 1 };
enum SignalBlocked { SIG_UNBLOCKED = 0, SIG_BLOCKED = 1 };
enum SignalOutcome {
  DISPOSITION_FATAL = 0,
  DISPOSITION_USER_HANDLER = 1,
  DISPOSITION_IGNORED = 2,
};
struct SignalEvent : public BaseEvent {
  /**
   * Signal |signo| is the signum, and |deterministic| is true
   * for deterministically-delivered signals (see
   * record_signal.cc).
   */
  SignalEvent(const siginfo_t& siginfo, SignalDeterministic deterministic,
              Task* t);
  SignalEvent(int signo, SignalDeterministic deterministic, SupportedArch arch)
      : BaseEvent(HAS_EXEC_INFO, arch), deterministic(deterministic) {
    memset(&siginfo, 0, sizeof(siginfo));
    siginfo.si_signo = signo;
  }

  /**
   * For SIGILL, SIGFPE, SIGSEGV, SIGBUS and SIGTRAP this is si_addr.
   * For other signals this is zero.
   */
  uint64_t signal_data() const {
    switch (siginfo.si_signo) {
      case SIGILL:
      case SIGFPE:
      case SIGSEGV:
      case SIGBUS:
      case SIGTRAP:
        return (uint64_t)siginfo.si_addr;
      default:
        return 0;
    }
  }

  void set_signal_data(uint64_t data) {
    switch (siginfo.si_signo) {
      case SIGILL:
      case SIGFPE:
      case SIGSEGV:
      case SIGBUS:
      case SIGTRAP:
        siginfo.si_addr = (void*)data;
        break;
    }
  }

  // Signal info
  siginfo_t siginfo;
  // True if this signal will be deterministically raised as the
  // side effect of retiring an instruction during replay, for
  // example |load $r 0x0| deterministically raises SIGSEGV.
  SignalDeterministic deterministic;
};

/**
 * Syscall events track syscalls through entry into the kernel,
 * processing in the kernel, and exit from the kernel.
 *
 * This also models interrupted syscalls.  During recording, only
 * descheduled buffered syscalls /push/ syscall interruptions; all
 * others are detected at exit time and transformed into syscall
 * interruptions from the original, normal syscalls.
 *
 * Normal system calls (interrupted or not) record two events: ENTERING_SYSCALL
 * and EXITING_SYSCALL. If the process exits before the syscall exit (because
 * this is an exit/exit_group syscall or the process gets SIGKILL), there's no
 * syscall exit event.
 *
 * When PTRACE_SYSCALL is used, there will be three events:
 * ENTERING_SYSCALL_PTRACE to run the process until it gets into the kernel,
 * then ENTERING_SYSCALL and EXITING_SYSCALL. We need three events to handle
 * PTRACE_SYSCALL with clone/fork/vfork and execve. The tracee must run to
 * the ENTERING_SYSCALL_PTRACE state, allow a context switch so the ptracer
 * can modify tracee registers, then perform ENTERING_SYSCALL (which actually
 * creates the new task or does the exec), allow a context switch so the
 * ptracer can modify the new task or post-exec state in a PTRACE_EVENT_EXEC/
 * CLONE/FORK/VFORK, then perform EXITING_SYSCALL to get into the correct
 * post-syscall state.
 *
 * When PTRACE_SYSEMU is used, there will only be one event: an
 * ENTERING_SYSCALL_PTRACE.
 */
enum SyscallState {
  // Not present in trace. Just a dummy value.
  NO_SYSCALL,
  // Run to the given register state and enter the kernel but don't
  // perform any system call processing yet.
  ENTERING_SYSCALL_PTRACE,
  // Run to the given register state and enter the kernel, if not already
  // there due to a ENTERING_SYSCALL_PTRACE, and then perform the initial part
  // of the system call (any work required before issuing a during-system-call
  // ptrace event).
  ENTERING_SYSCALL,
  // Not present in trace.
  PROCESSING_SYSCALL,
  // Already in the kernel. Perform the final part of the system call and exit
  // with the recorded system call result.
  EXITING_SYSCALL
};
struct SyscallEvent : public BaseEvent {
  /** Syscall |syscallno| is the syscall number. */
  SyscallEvent(int syscallno, SupportedArch arch)
      : BaseEvent(HAS_EXEC_INFO, arch),
        regs(arch),
        desched_rec(nullptr),
        state(NO_SYSCALL),
        number(syscallno),
        switchable(PREVENT_SWITCH),
        is_restart(false),
        failed_during_preparation(false),
        in_sysemu(false) {}
  // The original (before scratch is set up) arguments to the
  // syscall passed by the tracee.  These are used to detect
  // restarted syscalls.
  Registers regs;
  // If this is a descheduled buffered syscall, points at the
  // record for that syscall.
  remote_ptr<const struct syscallbuf_record> desched_rec;

  SyscallState state;
  // Syscall number.
  int number;
  // Records the switchable state when this syscall was prepared
  Switchable switchable;
  // True when this syscall was restarted after a signal interruption.
  bool is_restart;
  // True when this syscall failed during preparation.
  bool failed_during_preparation;
  // Syscall is being emulated via PTRACE_SYSEMU.
  bool in_sysemu;
};

struct syscall_interruption_t {
  syscall_interruption_t(){};
};
static const syscall_interruption_t interrupted;

/**
 * Sum type for all events (well, a C++ approximation thereof).  An
 * Event always has a definted EventType.  It can be down-casted to
 * one of the leaf types above iff the type tag is correct.
 */
struct Event {
  Event() : event_type(EV_UNASSIGNED) {}
  Event(EventType type, HasExecInfo info, SupportedArch arch)
      : event_type(type), base(info, arch) {}
  Event(const DeschedEvent& ev) : event_type(EV_DESCHED), desched(ev) {}
  Event(const SignalEvent& ev) : event_type(EV_SIGNAL), signal(ev) {}
  Event(const SyscallEvent& ev) : event_type(EV_SYSCALL), syscall(ev) {}
  Event(const syscall_interruption_t&, const SyscallEvent& ev)
      : event_type(EV_SYSCALL_INTERRUPTION), syscall(ev) {}
  /**
   * Re-construct this from an encoding created by
   * |Event::encode()|.
   */
  Event(EncodedEvent e);

  Event(const Event& o);
  ~Event();
  Event& operator=(const Event& o);

  // Events can always be cased to BaseEvent regardless of the
  // current concrete type, because all constituent types
  // inherit from BaseEvent.
  BaseEvent& Base() { return base; }
  const BaseEvent& Base() const { return base; }

  DeschedEvent& Desched() {
    assert(EV_DESCHED == event_type);
    return desched;
  }
  const DeschedEvent& Desched() const {
    assert(EV_DESCHED == event_type);
    return desched;
  }

  SignalEvent& Signal() {
    assert(is_signal_event());
    return signal;
  }
  const SignalEvent& Signal() const {
    assert(is_signal_event());
    return signal;
  }

  SyscallEvent& Syscall() {
    assert(is_syscall_event());
    return syscall;
  }
  const SyscallEvent& Syscall() const {
    assert(is_syscall_event());
    return syscall;
  }

  enum {
    // Deterministic signals are encoded as (signum | DET_SIGNAL_BIT).
    DET_SIGNAL_BIT = 0x80
  };

  /**
   * Return an encoding of this event that can be cheaply
   * serialized.  The encoding is lossy.
   */
  EncodedEvent encode() const;

  /**
   * Return true if a tracee at this event has meaningful
   * execution info (registers etc.)  that rr should record.
   * "Meaningful" means that the same state will be seen when
   * reaching this event during replay.
   */
  HasExecInfo record_exec_info() const;

  HasExecInfo has_exec_info() const { return base.has_exec_info; }

  bool has_ticks_slop() const;

  /**
   * Return true if this is one of the indicated type of events.
   */
  bool is_signal_event() const;
  bool is_syscall_event() const;

  /**
   * Dump info about this to INFO log.
   *
   * Note: usually you want to use |LOG(info) << event;|.
   */
  void log() const;

  /** Return a string describing this. */
  std::string str() const;

  /**
   * Dynamically change the type of this.  Only a small number
   * of type changes are allowed.
   */
  void transform(EventType new_type);

  /** Return the current type of this. */
  EventType type() const { return event_type; }

  /** Return the architecture associated with this. */
  SupportedArch arch() const { return base.arch(); }

  /** Change the architecture for this event. */
  void set_arch(SupportedArch a) { base.arch_ = a; }

  /** Return a string naming |ev|'s type. */
  std::string type_name() const;

  /** Return an event of type EV_NOOP. */
  static Event noop(SupportedArch arch) {
    return Event(EV_NOOP, NO_EXEC_INFO, arch);
  }

private:
  EventType event_type;
  union {
    BaseEvent base;
    DeschedEvent desched;
    SignalEvent signal;
    SyscallEvent syscall;
  };
};

inline static std::ostream& operator<<(std::ostream& o, const Event& ev) {
  return o << ev.str();
}

inline static std::ostream& operator<<(std::ostream& o,
                                       const EncodedEvent& ev) {
  return o << Event(ev);
}

const char* state_name(SyscallState state);

} // namespace rr

#endif // EVENT_H_
