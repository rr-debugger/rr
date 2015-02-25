/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_SESSION_H_
#define RR_REPLAY_SESSION_H_

#include <memory>

#include "CPUIDBugDetector.h"
#include "DiversionSession.h"
#include "EmuFs.h"
#include "Session.h"

struct syscallbuf_hdr;

/**
 * The state of a (dis)arm-desched-event ioctl that's being processed.
 */
enum ReplayDeschedType {
  DESCHED_ARM,
  DESCHED_DISARM
};
enum ReplayDeschedEnterExit {
  DESCHED_ENTER,
  DESCHED_EXIT
};
struct ReplayDeschedState {
  /* Is this an arm or disarm request? */
  ReplayDeschedType type;
  /* What's our next step to retire the ioctl? */
  ReplayDeschedEnterExit state;
};

/**
 * The state of a syscallbuf flush that's being processed.  Syscallbuf
 * flushes are an odd duck among the trace-step types (along with the
 * desched step above), because they must maintain extra state in
 * order to know which commands to issue when being resumed after an
 * interruption.  So the process of flushing the syscallbuf will
 * mutate this state in between attempts to retire the step.
 */
enum ReplayFlushBufferedSyscallStep {
  FLUSH_START,
  FLUSH_ARM,
  FLUSH_ENTER,
  FLUSH_EXIT,
  FLUSH_DISARM,
  FLUSH_DONE
};
/**
 * ReplayFlushBufferedSyscallState is saved in Session and cloned with its
 * Session, so it needs to be simple data, i.e. not holding pointers to
 * per-Session data.
 */
struct ReplayFlushBufferedSyscallState {
  /* True when we need to write the syscallbuf data back to
   * the child. */
  bool need_buffer_restore;
  /* After the data is restored, the number of record bytes that
   * still need to be flushed. */
  size_t num_rec_bytes_remaining;
  /* The offset of the next syscall record in both the rr and child
   * buffers */
  size_t syscall_record_offset;
  /* The next step to take. */
  ReplayFlushBufferedSyscallStep state;
  /* Track the state of retiring desched arm/disarm ioctls, when
   * necessary. */
  ReplayDeschedState desched;
};

/**
 * Describes the next step to be taken in order to replay a trace
 * frame.
 */
enum ReplayTraceStepType {
  TSTEP_NONE,

  /* Enter/exit a syscall.  |syscall| describe what should be
   * done at entry/exit. */
  TSTEP_ENTER_SYSCALL,
  TSTEP_EXIT_SYSCALL,

  /* Advance to the deterministic signal |signo|. */
  TSTEP_DETERMINISTIC_SIGNAL,

  /* Advance until |target.ticks| have been retired and then
   * |target.ip| is reached. */
  TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT,

  /* Deliver signal |signo|. */
  TSTEP_DELIVER_SIGNAL,

  /* Replay the upcoming buffered syscalls.  |flush| tracks the
   * replay state.*/
  TSTEP_FLUSH_SYSCALLBUF,

  /* Replay until we enter the next syscall, then patch it. */
  TSTEP_PATCH_SYSCALL,

  /* Emulate arming or disarming the desched event.  |desched|
   * tracks the replay state. */
  TSTEP_DESCHED,

  /* Frame has been replayed, done. */
  TSTEP_RETIRE,
};

enum ExecOrEmulate {
  EXEC = 0,
  EMULATE = 1
};

enum ExecOrEmulateReturn {
  EXEC_RETURN = 0,
  EMULATE_RETURN = 1
};

/**
 * rep_trace_step is saved in Session and cloned with its Session, so it needs
 * to be simple data, i.e. not holding pointers to per-Session data.
 */
struct ReplayTraceStep {
  ReplayTraceStepType action;

  union {
    struct {
      /* The syscall number we expect to
       * enter/exit. */
      int number;
      /* Is the kernel entry and exit for this
       * syscall emulated, that is, not executed? */
      ExecOrEmulate emu;
    } syscall;

    int signo;

    struct {
      Ticks ticks;
      int signo;
    } target;

    ReplayFlushBufferedSyscallState flush;

    ReplayDeschedState desched;
  };
};

enum ReplayStatus {
  // Some execution was replayed. replay_step() can be called again.
  REPLAY_CONTINUE,
  // All tracees are dead. replay_step() should not be called again.
  REPLAY_EXITED
};

struct ReplayResult {
  ReplayStatus status;
  BreakStatus break_status;
};

/**
 * An indicator of how much progress the ReplaySession has made within a given
 * (TraceFrame::Time, Ticks) pair. These can only be used for comparisons, to
 * check whether two ReplaySessions are in the same state and to help
 * order their states temporally.
 */
class ReplayStepKey {
public:
  /**
   * Construct the "none" key; this value is before or equal to every other
   * key value.
   */
  ReplayStepKey() : action(TSTEP_NONE) {}
  explicit ReplayStepKey(ReplayTraceStepType action) : action(action) {}

  bool operator==(const ReplayStepKey& other) const {
    return action == other.action;
  }
  bool operator<(const ReplayStepKey& other) const {
    return action < other.action;
  }

  bool in_execution() const { return action != TSTEP_NONE; }
  int as_int() const { return (int)action; }

private:
  ReplayTraceStepType action;
};

/** Encapsulates additional session state related to replay. */
class ReplaySession : public Session {
public:
  typedef std::shared_ptr<ReplaySession> shr_ptr;

  ~ReplaySession();

  /**
   * Return a semantic copy of all the state managed by this,
   * that is the entire tracee tree and the state it depends on.
   * Any mutations of the returned Session can't affect the
   * state of this, and vice versa.
   *
   * This operation is also called "checkpointing" the replay
   * session.
   */
  shr_ptr clone();

  /**
   * Return true if we're in a state where it's OK to clone. For example,
   * we can't clone in some syscalls.
   */
  bool can_clone();

  /**
   * Like |clone()|, but return a session in "diversion" mode,
   * which allows free execution.
   */
  DiversionSession::shr_ptr clone_diversion();

  EmuFs& emufs() const { return *emu_fs; }

  /** Collect garbage files from this session's emufs. */
  void gc_emufs();

  TraceReader& trace_reader() { return trace_in; }
  const TraceReader& trace_reader() const { return trace_in; }

  /**
   * The trace record that we are working on --- the next event
   * for replay to reach.
   */
  const TraceFrame& current_trace_frame() const { return trace_frame; }

  /**
   * The Task for the current trace record.
   */
  Task* current_task() {
    finish_initializing();
    return find_task(trace_frame.tid());
  }

  /**
   * The current ReplayStepKey.
   */
  ReplayStepKey current_step_key() const {
    return ReplayStepKey(current_step.action);
  }

  /**
   * If we've finished replaying (all tracees terminated), return the last
   * Task that ran. Sometimes debuggers need this. Returns null if replay
   * hasn't finished yet.
   */
  Task* last_task() { return last_debugged_task; }

  /**
   * Create a replay session that will use the trace directory specified
   * by 'dir', or the latest trace if 'dir' is not supplied.
   */
  static shr_ptr create(const std::string& dir);

  struct StepConstraints {
    explicit StepConstraints(RunCommand command)
        : command(command), stop_at_time(0), ticks_target(0) {}
    RunCommand command;
    TraceFrame::Time stop_at_time;
    Ticks ticks_target;
    bool is_singlestep() const { return command == RUN_SINGLESTEP; }
  };
  /**
   * Take a single replay step.
   * Ensure we stop at event stop_at_time. If this is not specified,
   * optimizations may cause a replay_step to pass straight through
   * stop_at_time.
   * Outside of replay_step, no internal breakpoints will be set for any
   * task in this session.
   * Stop when the current event reaches stop_at_time (i.e. this event has
   * is the next event to be replayed).
   * If ticks_target is nonzero, stop before the current task's ticks
   * reaches ticks_target (but not too far before, unless we hit a breakpoint
   * or stop_at_time). Only useful for RUN_CONTINUE.
   * Always stops on a switch to a new task.
   */
  ReplayResult replay_step(const StepConstraints& constraints);
  ReplayResult replay_step(RunCommand command) {
    return replay_step(StepConstraints(command));
  }

  virtual ReplaySession* as_replay() { return this; }

  /**
   * Return true if |sig| is a signal that may be generated during
   * replay but should be ignored.  For example, SIGCHLD can be
   * delivered at almost point during replay when tasks exit, but it's
   * not part of the recording and shouldn't be delivered.
   *
   * TODO: can we do some clever sigprocmask'ing to avoid pending
   * signals altogether?
   */
  static bool is_ignored_signal(int sig);

  struct Flags {
    Flags() : redirect_stdio(false) {}
    Flags(const Flags& other) = default;
    bool redirect_stdio;
  };
  bool redirect_stdio() { return flags.redirect_stdio; }

  void set_flags(const Flags& flags) { this->flags = flags; }

private:
  ReplaySession(const std::string& dir)
      : emu_fs(EmuFs::create()),
        last_debugged_task(nullptr),
        trace_in(dir),
        trace_frame(),
        current_step() {
    advance_to_next_trace_frame(0);
  }

  ReplaySession(const ReplaySession& other)
      : Session(other),
        emu_fs(other.emu_fs->clone()),
        last_debugged_task(nullptr),
        trace_in(other.trace_in),
        trace_frame(other.trace_frame),
        current_step(other.current_step),
        cpuid_bug_detector(other.cpuid_bug_detector),
        flags(other.flags) {
    assert(!other.last_debugged_task);
  }

  /**
   * Set |t| as the last (debugged) task in this session.
   *
   * When we notify the debugger of process exit, it wants to be
   * able to poke around at that last task.  So we store it here
   * to allow processing debugger requests for it later.
   */
  void set_last_task(Task* t) {
    assert(!last_debugged_task);
    last_debugged_task = t;
  }

  const struct syscallbuf_hdr* syscallbuf_flush_buffer_hdr() {
    return (const struct syscallbuf_hdr*)syscallbuf_flush_buffer_array;
  }

  void setup_replay_one_trace_frame(Task* t);
  void advance_to_next_trace_frame(TraceFrame::Time stop_at_time);
  Completion emulate_signal_delivery(Task* oldtask, int sig,
                                     const StepConstraints& constraints);
  Completion try_one_trace_step(Task* t,
                                const StepConstraints& step_constraints);
  Completion cont_syscall_boundary(Task* t, ExecOrEmulate emu,
                                   const StepConstraints& constraints);
  Completion enter_syscall(Task* t, const StepConstraints& constraints);
  Completion exit_syscall(Task* t, const StepConstraints& constraints);
  Ticks get_ticks_slack(Task* t);
  void check_ticks_consistency(Task* t, const Event& ev);
  void check_pending_sig(Task* t);
  void continue_or_step(Task* t, RunCommand stepi, int64_t tick_period = 0);
  enum ExecStateType {
    UNKNOWN,
    NOT_AT_TARGET,
    AT_TARGET
  };
  TrapType compute_trap_type(Task* t, int target_sig,
                             SignalDeterministic deterministic,
                             ExecStateType exec_state, RunCommand stepi);
  bool is_debugger_trap(Task* t, int target_sig,
                        SignalDeterministic deterministic,
                        ExecStateType exec_state, RunCommand stepi);
  Completion advance_to(Task* t, const Registers& regs, int sig,
                        RunCommand stepi, Ticks ticks);
  Completion advance_to_ticks_target(Task* t,
                                     const StepConstraints& constraints);
  Completion emulate_deterministic_signal(Task* t, int sig,
                                          const StepConstraints& constraints);
  Completion emulate_async_signal(Task* t, int sig,
                                  const StepConstraints& constraints,
                                  Ticks ticks);
  Completion skip_desched_ioctl(Task* t, ReplayDeschedState* ds,
                                const StepConstraints& constraints);
  void prepare_syscallbuf_records(Task* t);
  Completion flush_one_syscall(Task* t, const StepConstraints& constraints);
  Completion flush_syscallbuf(Task* t, const StepConstraints& constraints);
  Completion patch_next_syscall(Task* t, const StepConstraints& constraints);

  std::shared_ptr<EmuFs> emu_fs;
  Task* last_debugged_task;
  TraceReader trace_in;
  TraceFrame trace_frame;
  ReplayTraceStep current_step;
  CPUIDBugDetector cpuid_bug_detector;
  Flags flags;
  /**
   * Buffer for recorded syscallbuf bytes.  By definition buffer flushes
   * must be replayed sequentially, so we can use one buffer for all
   * tracees.  At the start of the flush, the recorded bytes are read
   * back into this buffer.  Then they're copied back to the tracee
   * record-by-record, as the tracee exits those syscalls.
   * This needs to be word-aligned.
   */
  union {
    uint8_t syscallbuf_flush_buffer_array[SYSCALLBUF_BUFFER_SIZE];
    uint64_t align_padding;
  };
};

#endif // RR_REPLAY_SESSION_H_
