/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_EVENT_H_
#define RR_EVENT_H_

#include <ostream>
#include <stack>
#include <string>
#include <vector>

#include "Registers.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "preload/preload_interface.h"

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
  EV_SYSCALL_INTERRUPTION,
  // Not stored in trace, but synthesized when we reach the end of the trace.
  EV_TRACE_TERMINATION,

  // Events present in traces:

  // No associated data.
  EV_EXIT,
  // Scheduling signal interrupted the trace.
  EV_SCHED,
  // A disabled RDTSC or CPUID instruction.
  EV_INSTRUCTION_TRAP,
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
  // Use .signal.
  EV_SIGNAL,
  EV_SIGNAL_DELIVERY,
  EV_SIGNAL_HANDLER,
  // Use .syscall.
  EV_SYSCALL,

  EV_LAST
};

/**
 * Desched events track the fact that a tracee's desched-event
 * notification fired during a may-block buffered syscall, which rr
 * interprets as the syscall actually blocking (for a potentially
 * unbounded amount of time).  After the syscall exits, rr advances
 * the tracee to where the desched is "disarmed" by the tracee.
 */
struct DeschedEvent {
  /** Desched of |rec|. */
  DeschedEvent(remote_ptr<const struct syscallbuf_record> rec) : rec(rec) {}
  // Record of the syscall that was interrupted by a desched
  // notification.  It's legal to reference this memory /while
  // the desched is being processed only/, because |t| is in the
  // middle of a desched, which means it's successfully
  // allocated (but not yet committed) this syscall record.
  remote_ptr<const struct syscallbuf_record> rec;
};

struct SyscallbufFlushEvent {
  SyscallbufFlushEvent() {}
  std::vector<mprotect_record> mprotect_records;
};

enum SignalDeterministic { NONDETERMINISTIC_SIG = 0, DETERMINISTIC_SIG = 1 };
enum SignalResolvedDisposition {
  DISPOSITION_FATAL = 0,
  DISPOSITION_USER_HANDLER = 1,
  DISPOSITION_IGNORED = 2,
};
struct SignalEvent {
  /**
   * Signal |signo| is the signum, and |deterministic| is true
   * for deterministically-delivered signals (see
   * record_signal.cc).
   */
  SignalEvent(const siginfo_t& siginfo, SignalDeterministic deterministic,
              SignalResolvedDisposition disposition)
      : siginfo(siginfo),
        deterministic(deterministic),
        disposition(disposition) {}

  // Signal info
  siginfo_t siginfo;
  // True if this signal will be deterministically raised as the
  // side effect of retiring an instruction during replay, for
  // example |load $r 0x0| deterministically raises SIGSEGV.
  SignalDeterministic deterministic;
  SignalResolvedDisposition disposition;
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

struct OpenedFd {
  std::string path;
  int fd;
};

struct SyscallEvent {
  /** Syscall |syscallno| is the syscall number. */
  SyscallEvent(int syscallno, SupportedArch arch)
      : arch_(arch),
        regs(arch),
        desched_rec(nullptr),
        write_offset(-1),
        state(NO_SYSCALL),
        number(syscallno),
        switchable(PREVENT_SWITCH),
        is_restart(false),
        failed_during_preparation(false),
        in_sysemu(false) {}

  std::string syscall_name() const { return rr::syscall_name(number, arch()); }

  SupportedArch arch() const { return arch_; }
  /** Change the architecture for this event. */
  void set_arch(SupportedArch a) { arch_ = a; }

  SupportedArch arch_;
  // The original (before scratch is set up) arguments to the
  // syscall passed by the tracee.  These are used to detect
  // restarted syscalls.
  Registers regs;
  // If this is a descheduled buffered syscall, points at the
  // record for that syscall.
  remote_ptr<const struct syscallbuf_record> desched_rec;

  // Extra data for specific syscalls. Only used for exit events currently.
  // -1 to indicate there isn't one
  int64_t write_offset;
  std::vector<int> exec_fds_to_close;
  std::vector<OpenedFd> opened;

  SyscallState state;
  // Syscall number.
  int number;
  // Records the switchable state when this syscall was prepared
  Switchable switchable;
  // True when this syscall was restarted after a signal interruption.
  bool is_restart;
  // True when this syscall failed during preparation. This includes syscalls
  // that were interrupted by SIGSYS via seccomp, and clone system calls that
  // failed. These system calls failed no matter what the syscall-result
  // register says.
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
  Event(const DeschedEvent& ev) : event_type(EV_DESCHED), desched(ev) {}
  Event(EventType type, const SignalEvent& ev) : event_type(type), signal(ev) {}
  Event(const SyscallbufFlushEvent& ev)
      : event_type(EV_SYSCALLBUF_FLUSH), syscallbuf_flush(ev) {}
  Event(const SyscallEvent& ev) : event_type(EV_SYSCALL), syscall(ev) {}
  Event(const syscall_interruption_t&, const SyscallEvent& ev)
      : event_type(EV_SYSCALL_INTERRUPTION), syscall(ev) {}
  Event(const Event& o);
  ~Event();
  Event& operator=(const Event& o);

  DeschedEvent& Desched() {
    DEBUG_ASSERT(EV_DESCHED == event_type);
    return desched;
  }
  const DeschedEvent& Desched() const {
    DEBUG_ASSERT(EV_DESCHED == event_type);
    return desched;
  }

  SyscallbufFlushEvent& SyscallbufFlush() {
    DEBUG_ASSERT(EV_SYSCALLBUF_FLUSH == event_type);
    return syscallbuf_flush;
  }
  const SyscallbufFlushEvent& SyscallbufFlush() const {
    DEBUG_ASSERT(EV_SYSCALLBUF_FLUSH == event_type);
    return syscallbuf_flush;
  }

  SignalEvent& Signal() {
    DEBUG_ASSERT(is_signal_event());
    return signal;
  }
  const SignalEvent& Signal() const {
    DEBUG_ASSERT(is_signal_event());
    return signal;
  }

  SyscallEvent& Syscall() {
    DEBUG_ASSERT(is_syscall_event());
    return syscall;
  }
  const SyscallEvent& Syscall() const {
    DEBUG_ASSERT(is_syscall_event());
    return syscall;
  }

  bool record_regs() const;

  bool record_extra_regs() const;

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

  /** Return a string naming |ev|'s type. */
  std::string type_name() const;

  static Event noop() { return Event(EV_NOOP); }
  static Event trace_termination() { return Event(EV_TRACE_TERMINATION); }
  static Event instruction_trap() { return Event(EV_INSTRUCTION_TRAP); }
  static Event patch_syscall() { return Event(EV_PATCH_SYSCALL); }
  static Event sched() { return Event(EV_SCHED); }
  static Event seccomp_trap() { return Event(EV_SECCOMP_TRAP); }
  static Event syscallbuf_abort_commit() {
    return Event(EV_SYSCALLBUF_ABORT_COMMIT);
  }
  static Event syscallbuf_reset() { return Event(EV_SYSCALLBUF_RESET); }
  static Event grow_map() { return Event(EV_GROW_MAP); }
  static Event exit() { return Event(EV_EXIT); }
  static Event sentinel() { return Event(EV_SENTINEL); }

private:
  Event(EventType type) : event_type(type) {}

  EventType event_type;
  union {
    DeschedEvent desched;
    SignalEvent signal;
    SyscallEvent syscall;
    SyscallbufFlushEvent syscallbuf_flush;
  };
};

inline static std::ostream& operator<<(std::ostream& o, const Event& ev) {
  return o << ev.str();
}

const char* state_name(SyscallState state);

} // namespace rr

#endif // EVENT_H_
