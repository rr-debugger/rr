/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_EVENT_H_
#define RR_EVENT_H_

#include <assert.h>

#include <ostream>
#include <stack>
#include <string>

#include "registers.h"

enum EventType {
  EV_UNASSIGNED,
  EV_SENTINEL,
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
  // TODO: this is actually a pseudo-pseudosignal: it will never
  // appear in a trace, but is only used to communicate between
  // different parts of the recorder code that should be
  // refactored to not have to do that.
  EV_NOOP,
  EV_SCHED,
  EV_SEGV_RDTSC,
  EV_SYSCALLBUF_FLUSH,
  EV_SYSCALLBUF_ABORT_COMMIT,
  EV_SYSCALLBUF_RESET,
  // The trace was terminated before all tasks exited, most
  // likely because the recorder was sent a terminating signal.
  // There are no more trace frames coming, so the best thing to
  // do is probably to shut down.
  EV_TRACE_TERMINATION,
  // Like USR_EXIT, but recorded when the task is in an
  // "unstable" state in which we're not sure we can
  // synchronously wait for it to "really finish".
  EV_UNSTABLE_EXIT,
  // Uses the .desched struct below.
  EV_DESCHED,
  // Use .signal.
  EV_SIGNAL,
  EV_SIGNAL_DELIVERY,
  EV_SIGNAL_HANDLER,
  // Use .syscall.
  EV_SYSCALL,
  EV_SYSCALL_INTERRUPTION,
  EV_LAST
};

enum {
  STATE_SYSCALL_ENTRY = 0,
  STATE_SYSCALL_EXIT = 1
};

// Deterministic signals are encoded as (signum | DET_SIGNAL_BIT).
enum {
  DET_SIGNAL_BIT = 0x80
};

/**
 * An encoding of the relevant bits of |struct event| that can be
 * cheaply and easily serialized.
 */
union EncodedEvent {
  struct {
    int type : 6;
    int data : 22;
    // We allocate 2 bits for these so that they can have
    // a positive nonzero value.  It's awkward to use an
    // unsigned int for storage because |data| may have a
    // negative value.
    int state : 2;
    int has_exec_info : 2;
  };
  int encoded;

  bool operator==(const EncodedEvent& other) const {
    return encoded == other.encoded;
  }
  bool operator!=(const EncodedEvent& other) const { return !(*this == other); }

  // XXX x86-64 porting hazard. We should just add 'arch' to all events.
  SupportedArch arch() const { return x86; }
};

static_assert(sizeof(int) == sizeof(EncodedEvent), "Bit fields are messed up");
static_assert(EV_LAST < (1 << 5),
              "Allocate more bits to the |event_type| field");

enum {
  NO_EXEC_INFO = 0,
  HAS_EXEC_INFO
};

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
  BaseEvent(bool has_exec_info) : has_exec_info(has_exec_info) {}
  // When replaying an event is expected to leave the tracee in
  // the same execution state as during replay, the event has
  // meaningful execution info, and it should be recorded for
  // checking.  But some pseudosigs aren't recorded in the same
  // tracee state they'll be replayed, so the tracee exeuction
  // state isn't meaningful.
  bool has_exec_info;
};

/**
 * Desched events track the fact that a tracee's desched-event
 * notification fired during a may-block buffered syscall, which rr
 * interprets as the syscall actually blocking (for a potentially
 * unbounded amount of time).  After the syscall exits, rr advances
 * the tracee to where the desched is "disarmed" by the tracee.
 */
enum DeschedState {
  ARMING_DESCHED_EVENT,
  IN_SYSCALL,
  DISARMING_DESCHED_EVENT,
  DISARMED_DESCHED_EVENT
};
struct DeschedEvent : public BaseEvent {
  /** Desched of |rec|. */
  DeschedEvent(const struct syscallbuf_record* rec)
      : BaseEvent(NO_EXEC_INFO), rec(rec), state(IN_SYSCALL) {}
  // Record of the syscall that was interrupted by a desched
  // notification.  It's legal to reference this memory /while
  // the desched is being processed only/, because |t| is in the
  // middle of a desched, which means it's successfully
  // allocated (but not yet committed) this syscall record.
  const struct syscallbuf_record* rec;
  DeschedState state;
};

/**
 * Signal events track signals through the delivery phase, and if the
 * signal finds a sighandler, on to the end of the handling face.
 */
enum {
  NONDETERMINISTIC_SIG = 0,
  DETERMINISTIC_SIG = 1
};
struct SignalEvent : public BaseEvent {
  /**
   * Signal |sigo| is the signum, and |deterministic| is true
   * for deterministically-delivered signals (see
   * record_signal.cc).
   */
  SignalEvent(int signo, bool deterministic)
      : BaseEvent(HAS_EXEC_INFO),
        no(signo),
        deterministic(deterministic),
        delivered(false) {}
  // Signal number.
  int no;
  // True if this signal will be deterministically raised as the
  // side effect of retiring an instruction during replay, for
  // example |load $r 0x0| deterministically raises SIGSEGV.
  bool deterministic;
  // True when this signal has been delivered by a ptrace()
  // request.
  bool delivered;
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
 * During replay, we push interruptions to know when we need
 * to emulate syscall entry, since the kernel won't have set
 * things up for the tracee to restart on its own.

 */
enum SyscallState {
  NO_SYSCALL,
  ENTERING_SYSCALL,
  PROCESSING_SYSCALL,
  EXITING_SYSCALL
};
struct SyscallEvent : public BaseEvent {
  typedef std::stack<void*> ArgsStack;

  /** Syscall |syscallno| is the syscall number. */
  SyscallEvent(int syscallno)
      : BaseEvent(HAS_EXEC_INFO),
        regs(),
        desched_rec(nullptr),
        saved_args(),
        tmp_data_ptr(nullptr),
        tmp_data_num_bytes(-1),
        state(NO_SYSCALL),
        no(syscallno),
        is_restart(false) {}
  // The original (before scratch is set up) arguments to the
  // syscall passed by the tracee.  These are used to detect
  // restarted syscalls.
  Registers regs;
  // If this is a descheduled buffered syscall, points at the
  // record for that syscall.
  const struct syscallbuf_record* desched_rec;
  // When tasks enter syscalls that may block and so must be
  // prepared for a context-switch, and the syscall params
  // include (in)outparams that point to buffers, we need to
  // redirect those arguments to scratch memory.  This allows rr
  // to serialize execution of what may be multiple blocked
  // syscalls completing "simulatenously" (from rr's
  // perspective).  After the syscall exits, we restore the data
  // saved in scratch memory to the original buffers.
  //
  // Then during replay, we simply restore the saved data to the
  // tracee's passed-in buffer args and continue on.
  //
  // The array |saved_arg_ptr| stores the original callee
  // pointers that we replaced with pointers into the
  // syscallbuf.  |tmp_data_num_bytes| is the number of bytes
  // we'll be saving across//all* buffer outparams.  (We can
  // save one length value because all the tmp pointers into
  // scratch are contiguous.)  |tmp_data_ptr| /usually/ points
  // at |scratch_ptr|, except ...
  //
  // ... a fly in this ointment is may-block buffered syscalls.
  // If a task blocks in one of those, it will look like it just
  // entered a syscall that needs a scratch buffer.  However,
  // it's too late at that point to fudge the syscall args,
  // because processing of the syscall has already begun in the
  // kernel.  But that's OK: the syscallbuf code has already
  // swapped out the original buffer-pointers for pointers into
  // the syscallbuf (which acts as its own scratch memory).  We
  // just have to worry about setting things up properly for
  // replay.
  //
  // The descheduled syscall will "abort" its commit into the
  // syscallbuf, so the outparam data won't actually be saved
  // there (and thus, won't be restored during replay).  During
  // replay, we have to restore them like we restore the
  // non-buffered-syscall scratch data.
  //
  // What we do is add another level of indirection to the
  // "scratch pointer", through |tmp_data_ptr|.  Usually that
  // will point at |scratch_ptr|, for unbuffered syscalls.  But
  // for desched'd buffered ones, it will point at the region of
  // the syscallbuf that's being used as "scratch".  We'll save
  // that region during recording and restore it during replay
  // without caring which scratch space it points to.
  //
  // (The recorder code has to be careful, however, not to
  // attempt to copy-back syscallbuf tmp data to the "original"
  // buffers.  The syscallbuf code will do that itself.)
  ArgsStack saved_args;
  void* tmp_data_ptr;
  ssize_t tmp_data_num_bytes;
  SyscallState state;
  // Syscall number.
  int no;
  // Nonzero when this syscall was restarted after a signal
  // interruption.
  bool is_restart;
};

struct syscall_interruption_t {};
static const syscall_interruption_t interrupted;

/**
 * Sum type for all events (well, a C++ approximation thereof).  An
 * Event always has a definted EventType.  It can be down-casted to
 * one of the leaf types above iff the type tag is correct.
 */
struct Event {
  Event() : event_type(EV_UNASSIGNED) {}
  Event(EventType type, const BaseEvent& ev) : event_type(type), base(ev) {}
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
  bool has_exec_info() const;

  /**
   * See long comment at |Task::maybe_save_rbc_slop()|.
   */
  bool has_rbc_slop() const;

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

  /** Return an event of type EV_NOOP. */
  static Event noop() { return Event(EV_NOOP, NO_EXEC_INFO); }

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

/**
 * Return the symbolic name of |state|, or "???state" if unknown.
 */
const char* statename(int state);

#endif // EVENT_H_
