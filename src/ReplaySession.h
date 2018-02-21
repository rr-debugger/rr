/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_SESSION_H_
#define RR_REPLAY_SESSION_H_

#include <memory>
#include <set>

#include "AddressSpace.h"
#include "CPUIDBugDetector.h"
#include "DiversionSession.h"
#include "EmuFs.h"
#include "Session.h"
#include "Task.h"

struct syscallbuf_hdr;

namespace rr {

class ReplayTask;

/**
 * ReplayFlushBufferedSyscallState is saved in Session and cloned with its
 * Session, so it needs to be simple data, i.e. not holding pointers to
 * per-Session data.
 */
struct ReplayFlushBufferedSyscallState {
  /* An internal breakpoint is set at this address */
  uintptr_t stop_breakpoint_addr;
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

  /* Exit the task */
  TSTEP_EXIT_TASK,

  /* Frame has been replayed, done. */
  TSTEP_RETIRE,
};

/**
 * rep_trace_step is saved in Session and cloned with its Session, so it needs
 * to be simple data, i.e. not holding pointers to per-Session data.
 */
struct ReplayTraceStep {
  ReplayTraceStepType action;

  union {
    struct {
      /* The architecture of the syscall */
      SupportedArch arch;
      /* The syscall number we expect to
       * enter/exit. */
      int number;
    } syscall;

    struct {
      Ticks ticks;
      int signo;
    } target;

    ReplayFlushBufferedSyscallState flush;
  };
};

enum ReplayStatus {
  // Some execution was replayed. replay_step() can be called again.
  REPLAY_CONTINUE,
  // All tracees are dead. replay_step() should not be called again.
  REPLAY_EXITED
};

struct ReplayResult {
  ReplayResult(ReplayStatus status = REPLAY_CONTINUE)
      : status(status), did_fast_forward(false) {}
  ReplayStatus status;
  BreakStatus break_status;
  // True if we did a fast-forward operation, in which case
  // break_status.singlestep_complete might indicate the completion of more
  // than one instruction.
  bool did_fast_forward;
};

/**
 * An indicator of how much progress the ReplaySession has made within a given
 * (FrameTime, Ticks) pair. These can only be used for comparisons, to
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

  virtual Task* new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                         SupportedArch a) override;

  using Session::clone;
  /**
   * Return a semantic copy of all the state managed by this,
   * that is the entire tracee tree and the state it depends on.
   * Any mutations of the returned Session can't affect the
   * state of this, and vice versa.
   *
   * This operation is also called "checkpointing" the replay
   * session.
   *
   * The returned clone is only partially initialized. This uses less
   * system resources than a fully-initialized session, so if you're going
   * to keep a session around inactive, keep the clone and not the original
   * session. Partially initialized sessions automatically finish
   * initializing when necessary.
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

  TraceReader& trace_reader() { return trace_in; }
  const TraceReader& trace_reader() const { return trace_in; }

  /**
   * The trace record that we are working on --- the next event
   * for replay to reach.
   */
  const TraceFrame& current_trace_frame() const { return trace_frame; }
  /**
   * Time of the current frame
   */
  FrameTime current_frame_time() const { return trace_frame.time(); }

  /**
   * The Task for the current trace record.
   */
  ReplayTask* current_task() {
    finish_initializing();
    return find_task(trace_frame.tid());
  }

  ReplayTask* find_task(pid_t rec_tid) const;
  ReplayTask* find_task(const TaskUid& tuid) const;

  /**
   * Returns true if the next step for this session is to exit a syscall with
   * the given number.
   */
  bool next_step_is_successful_syscall_exit(int syscallno);

  /**
   * The current ReplayStepKey.
   */
  ReplayStepKey current_step_key() const {
    return ReplayStepKey(current_step.action);
  }

  Ticks ticks_at_start_of_current_event() const {
    return ticks_at_start_of_event;
  }

  /**
   * Create a replay session that will use the trace directory specified
   * by 'dir', or the latest trace if 'dir' is not supplied.
   */
  static shr_ptr create(const std::string& dir);

  struct StepConstraints {
    explicit StepConstraints(RunCommand command)
        : command(command), stop_at_time(0), ticks_target(0) {}
    RunCommand command;
    FrameTime stop_at_time;
    Ticks ticks_target;
    // When the RunCommand is RUN_SINGLESTEP_FAST_FORWARD, stop if the next
    // singlestep would enter one of the register states in this list.
    // RUN_SINGLESTEP_FAST_FORWARD will always singlestep at least once
    // regardless.
    std::vector<const Registers*> stop_before_states;

    bool is_singlestep() const {
      return command == RUN_SINGLESTEP ||
             command == RUN_SINGLESTEP_FAST_FORWARD;
    }
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

  virtual ReplaySession* as_replay() override { return this; }

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
    Flags() : redirect_stdio(false), share_private_mappings(false) {}
    Flags(const Flags& other) = default;
    bool redirect_stdio;
    bool share_private_mappings;
  };
  bool redirect_stdio() { return flags.redirect_stdio; }
  bool share_private_mappings() { return flags.share_private_mappings; }

  void set_flags(const Flags& flags) { this->flags = flags; }

  typedef std::set<MemoryRange, MappingComparator> MemoryRanges;
  /**
   * Returns an ordered set of MemoryRanges representing the address space
   * that is never allocated by any process in the whole lifetime of the trace.
   */
  static MemoryRanges always_free_address_space(const TraceReader& reader);

  double get_trace_start_time();

private:
  ReplaySession(const std::string& dir);
  ReplaySession(const ReplaySession& other);

  ReplayTask* revive_task_for_exec();
  ReplayTask* setup_replay_one_trace_frame(ReplayTask* t);
  void advance_to_next_trace_frame();
  Completion emulate_signal_delivery(ReplayTask* oldtask, int sig);
  Completion try_one_trace_step(ReplayTask* t,
                                const StepConstraints& step_constraints);
  Completion cont_syscall_boundary(ReplayTask* t,
                                   const StepConstraints& constraints);
  Completion enter_syscall(ReplayTask* t, const StepConstraints& constraints);
  Completion exit_syscall(ReplayTask* t);
  Completion exit_task(ReplayTask* t);
  bool handle_unrecorded_cpuid_fault(ReplayTask* t,
                                     const StepConstraints& constraints);
  void check_ticks_consistency(ReplayTask* t, const Event& ev);
  void check_pending_sig(ReplayTask* t);
  Completion continue_or_step(ReplayTask* t, const StepConstraints& constraints,
                              TicksRequest tick_request,
                              ResumeRequest resume_how = RESUME_SYSEMU);
  Completion advance_to_ticks_target(ReplayTask* t,
                                     const StepConstraints& constraints);
  Completion emulate_deterministic_signal(ReplayTask* t, int sig,
                                          const StepConstraints& constraints);
  Completion emulate_async_signal(ReplayTask* t,
                                  const StepConstraints& constraints,
                                  Ticks ticks);
  void prepare_syscallbuf_records(ReplayTask* t);
  Completion flush_syscallbuf(ReplayTask* t,
                              const StepConstraints& constraints);
  Completion patch_next_syscall(ReplayTask* t,
                                const StepConstraints& constraints);
  void check_approaching_ticks_target(ReplayTask* t,
                                      const StepConstraints& constraints,
                                      BreakStatus& break_status);

  void clear_syscall_bp();

  std::shared_ptr<EmuFs> emu_fs;
  TraceReader trace_in;
  TraceFrame trace_frame;
  ReplayTraceStep current_step;
  Ticks ticks_at_start_of_event;
  CPUIDBugDetector cpuid_bug_detector;
  siginfo_t last_siginfo_;
  Flags flags;
  bool did_fast_forward;

  // The clock_gettime(CLOCK_MONOTONIC) timestamp of the first trace event, used
  // during 'replay' to calculate the elapsed time between the first event and 
  // all other recorded events in the timeline during the 'record' phase.
  double trace_start_time;

  std::shared_ptr<AddressSpace> syscall_bp_vm;
  remote_code_ptr syscall_bp_addr;
};

} // namespace rr

#endif // RR_REPLAY_SESSION_H_
