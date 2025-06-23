/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_SESSION_H_
#define RR_REPLAY_SESSION_H_

#include <memory>
#include <ostream>
#include <set>

#include "AddressSpace.h"
#include "CPUIDBugDetector.h"
#include "DiversionSession.h"
#include "TraceStream.h"
#include "EmuFs.h"
#include "Session.h"
#include "Task.h"
#include "fast_forward.h"

struct syscallbuf_hdr;

namespace rr {

class ReplayTask;

/**
 * ReplayFlushBufferedSyscallState is saved in Session and cloned with its
 * Session, so it needs to be simple data, i.e. not holding pointers to
 * per-Session data.
 */
struct ReplayFlushBufferedSyscallState {
  /* The offset in the syscallbuf (in 8-byte units) at which we want to stop */
  uintptr_t stop_breakpoint_offset;
  /* This includes slop */
  Ticks recorded_ticks;
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

  /* Replay until we exit the next syscall, then patch it. */
  TSTEP_PATCH_AFTER_SYSCALL,

  /* Replay until we hit the ip recorded in the event, then patch the site. */
  TSTEP_PATCH_IP,

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
      // Not remote_code_ptr because this has to have plain data
      uint64_t in_syscallbuf_syscall_hook;
    } target;

    ReplayFlushBufferedSyscallState flush;
  };
};

enum ReplayStatus {
  // Some execution was replayed. replay_step() can be called again.
  REPLAY_CONTINUE,
  // All tracees are dead. replay_step() should not be called again.
  REPLAY_EXITED,
  // Replay failed and this session is dead, but trying again with a
  // new session might work.
  REPLAY_TRANSIENT_ERROR,
};

struct ReplayResult {
  ReplayResult(ReplayStatus status = REPLAY_CONTINUE)
      : status(status), did_fast_forward(false), incomplete_fast_forward(false) {}
  ReplayStatus status;
  BreakStatus break_status;
  // True if we did a fast-forward operation, in which case
  // break_status.singlestep_complete might indicate the completion of more
  // than one instruction.
  bool did_fast_forward;
  // True if we fast-forward-singlestepped a string instruction but it has at least
  // one iteration to go. did_fast_forward may be false in this case if the
  // instruction executes exactly twice.
  bool incomplete_fast_forward;
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
class ReplaySession final : public Session {
public:
  typedef std::shared_ptr<ReplaySession> shr_ptr;

  ~ReplaySession();

  virtual Task* new_task(pid_t tid, pid_t rec_tid, uint32_t serial,
                         SupportedArch a, const std::string& name) override;

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
  bool next_step_is_successful_exec_syscall_exit();

  /**
   * The current ReplayStepKey.
   */
  ReplayStepKey current_step_key() const {
    return ReplayStepKey(current_step.action);
  }

  Ticks ticks_at_start_of_current_event() const {
    return ticks_at_start_of_event;
  }

  struct Flags {
    Flags()
      : redirect_stdio(false)
      , share_private_mappings(false)
      , replay_stops_at_first_execve(false)
      , cpu_unbound(false)
      , transient_errors_fatal(false)
      , intel_pt_start_checking_event(-1) {}
    Flags(const Flags&) = default;
    bool redirect_stdio;
    std::string redirect_stdio_file;
    bool share_private_mappings;
    bool replay_stops_at_first_execve;
    bool cpu_unbound;
    bool transient_errors_fatal;
    FrameTime intel_pt_start_checking_event;
  };

  /**
   * Create a replay session that will use the trace directory specified
   * by 'dir', or the latest trace if 'dir' is not supplied.
   */
  static shr_ptr create(const std::string& dir, const Flags& flags);

  struct StepConstraints {
    explicit StepConstraints(RunCommand command)
        : command(command), ticks_target(0) {}
    RunCommand command;
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
   * Outside of replay_step, no internal breakpoints will be set for any
   * task in this session.
   * If ticks_target is nonzero, stop before the current task's ticks
   * reaches ticks_target (but not too far before, unless we hit a breakpoint).
   * Only useful for RUN_CONTINUE.
   * Always stops on a switch to a new task.
   */
  ReplayResult replay_step(const StepConstraints& constraints);
  ReplayResult replay_step(RunCommand command) {
    return replay_step(StepConstraints(command));
  }

  virtual ReplaySession* as_replay() override { return this; }
  virtual bool need_performance_counters() const override { return !replay_stops_at_first_execve_; }

  SupportedArch arch() { return trace_in.arch(); }

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

  const Flags& flags() const { return flags_; }

  typedef std::set<MemoryRange, MappingComparator> MemoryRanges;
  enum PerfTradeoff {
    FAST,
    ACCURATE,
  };
  /**
   * Returns an ordered set of MemoryRanges representing the address space
   * that is never allocated by any process in the whole lifetime of the trace.
   * When `perf_tradeoff` is `FAST`, we try to quickly return whatever we can.
   * When it's `ACCURATE`, we do a much slower pass that can identify more memory.
   * `ACCURATE` will always identify a superset of the memory identified by
   * `FAST`.
   * This memoizes its results so it's fast to call many times.
   */
  const MemoryRanges& always_free_address_space(
    PerfTradeoff perf_tradeoff = ACCURATE);
  static void delete_range(ReplaySession::MemoryRanges& ranges,
                           const MemoryRange& r);

  double get_trace_start_time();

  virtual TraceStream* trace_stream() override { return &trace_in; }

  virtual BindCPU cpu_binding() const override;

  bool has_trace_quirk(TraceReader::TraceQuirks quirk) { return trace_in.quirks() & quirk; }

  virtual int tracee_output_fd(int dflt) override {
    return tracee_output_fd_.get() ? tracee_output_fd_->get() : dflt;
  }

  /**
   * Get ready to detach these tasks and reattach them in a child process. Call this
   * before forking the child.
   */
  void prepare_to_detach_tasks();
  /**
   * This ReplaySession is in a forked child. The real ReplaySession is still running in
   * the parent, so we don't really own tasks and other shared resources. Forget about
   * them so we don't try to tear them down when this ReplaySession is destroyed.
   */
  void forget_tasks();
  /**
   * The shared resources associated with this ReplaySession are being transferred to
   * the child process `new_ptracer`. Prepare them for transfer (e.g. ptrace-detach the
   * tracees) and prepare them to be traced by `new_ptracer`, and forget about them.
   * `new_sock_fd` is the new control fd pushed into all tasks.
   */
  void detach_tasks(pid_t new_ptracer, ScopedFd& new_tracee_socket_receiver);
  /**
   * The shared resources associated with this ReplaySession are being transferred to
   * the child process `new_ptracer`. Receive them in the child process by ptrace-attaching
   * to them etc.
   * `new_sock_fd` is the control fd that has been assigned to all tasks,
   * `new_sock_receiver_fd` is its receiver end.
   */
  void reattach_tasks(ScopedFd new_tracee_socket, ScopedFd new_tracee_socket_receiver);

  void notify_detected_transient_error() { detected_transient_error_ = true; }

  void set_suppress_stdio_before_event(FrameTime event) { suppress_stdio_before_event_ = event; }
  bool mark_stdio() const override;
  bool echo_stdio() const;

private:
  ReplaySession(const std::string& dir, const Flags& flags);
  ReplaySession(const ReplaySession& other);

  void check_virtual_address_size() const;

  ReplayTask* revive_task_for_exec();
  ReplayTask* setup_replay_one_trace_frame(ReplayTask* t);
  void advance_to_next_trace_frame();
  Completion emulate_signal_delivery(ReplayTask* oldtask);
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
                                  Ticks ticks,
                                  remote_code_ptr in_syscallbuf_syscall_hook);
  void prepare_syscallbuf_records(ReplayTask* t, Ticks ticks);
  Completion flush_syscallbuf(ReplayTask* t,
                              const StepConstraints& constraints);
  Completion patch_next_syscall(ReplayTask* t,
                                const StepConstraints& constraints,
                                bool before_syscall);
  Completion patch_ip(ReplayTask* t, const StepConstraints& constraints);
  void apply_patch_data(ReplayTask* t);
  void check_approaching_ticks_target(ReplayTask* t,
                                      const StepConstraints& constraints,
                                      BreakStatus& break_status);

  void clear_syscall_bp();

  std::shared_ptr<EmuFs> emu_fs;
  std::shared_ptr<ScopedFd> tracee_output_fd_;
  TraceReader trace_in;
  TraceFrame trace_frame;
  ReplayTraceStep current_step;
  Ticks ticks_at_start_of_event;
  CPUIDBugDetector cpuid_bug_detector;
  siginfo_t last_siginfo_;
  Flags flags_;
  FastForwardStatus fast_forward_status;
  TaskUid last_task_tuid;
  bool skip_next_execution_event;
  bool replay_stops_at_first_execve_;
  bool detected_transient_error_;

  // The clock_gettime(CLOCK_MONOTONIC) timestamp of the first trace event, used
  // during 'replay' to calculate the elapsed time between the first event and
  // all other recorded events in the timeline during the 'record' phase.
  double trace_start_time;

  FrameTime suppress_stdio_before_event_;

  std::shared_ptr<AddressSpace> syscall_bp_vm;
  remote_code_ptr syscall_bp_addr;

  std::shared_ptr<MemoryRanges> always_free_address_space_fast;
  std::shared_ptr<MemoryRanges> always_free_address_space_accurate;
};

void emergency_check_intel_pt(ReplayTask* t, std::ostream& stream);

} // namespace rr

#endif // RR_REPLAY_SESSION_H_
