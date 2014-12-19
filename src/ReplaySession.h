/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REPLAY_SESSION_H_
#define RR_REPLAY_SESSION_H_

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

  /* Frame has been replayed, done. */
  TSTEP_RETIRE,

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
      /* The number of outparam arguments that are
       * set from what was recorded.
       * Only used when action is TSTEP_EXIT_SYSCALL. */
      ssize_t num_emu_args;
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
   * Like |clone()|, but return a session in "diversion" mode,
   * which allows free execution.
   */
  DiversionSession::shr_ptr clone_diversion();

  EmuFs& emufs() const { return *emu_fs; }

  /** Collect garbage files from this session's emufs. */
  void gc_emufs();

  TraceReader& trace_reader() { return trace_in; }

  /**
   * The trace record that we are working on --- the next event
   * for replay to reach.
   */
  const TraceFrame& current_trace_frame() const { return trace_frame; }

  /**
   * The Task for the current trace record.
   */
  Task* current_task() const { return find_task(trace_frame.tid()); }

  /**
   * Set |tgid| as the one that's being debugged in this
   * session.
   *
   * Little hack: technically replayer doesn't know about the
   * fact that GdbConnection hides all but one tgid from the gdb
   * client.  But to recognize the last_task below (another
   * little hack), we need to known when an exiting thread from
   * the target task group is the last.
   */
  void set_debugged_tgid(pid_t tgid) {
    assert(0 == tgid_debugged);
    tgid_debugged = tgid;
  }
  pid_t debugged_tgid() const { return tgid_debugged; }

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

  enum ReplayStatus {
    // Some execution was replayed. replay_step() can be called again.
    REPLAY_CONTINUE,
    // All tracees are dead. replay_step() should not be called again.
    REPLAY_EXITED
  };
  struct ReplayResult {
    ReplayStatus status;
    // When status == STEP_CONTINUE
    BreakStatus break_status;
  };
  /**
   * Take a single replay step.
   * Ensure we stop at event stop_at_time. If this is not specified,
   * optimizations may cause a replay_step to pass straight through
   * stop_at_time.
   */
  ReplayResult replay_step(RunCommand command = RUN_CONTINUE,
                           TraceFrame::Time stop_at_time = 0);

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

  bool redirect_stdio() { return redirect_stdio_; }

  void set_redirect_stdio(bool redirect) { redirect_stdio_ = redirect; }

private:
  ReplaySession(const std::string& dir)
      : emu_fs(EmuFs::create()),
        last_debugged_task(nullptr),
        tgid_debugged(0),
        trace_in(dir),
        trace_frame(),
        current_step(),
        redirect_stdio_(false) {
    advance_to_next_trace_frame(0);
  }

  ReplaySession(const ReplaySession& other)
      : emu_fs(other.emu_fs->clone()),
        last_debugged_task(nullptr),
        tgid_debugged(other.tgid_debugged),
        trace_in(other.trace_in),
        trace_frame(other.trace_frame),
        current_step(other.current_step),
        cpuid_bug_detector(other.cpuid_bug_detector),
        redirect_stdio_(other.redirect_stdio_) {
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

  void copy_state_to(Session& dest, EmuFs& dest_emu_fs);

  const struct syscallbuf_hdr* syscallbuf_flush_buffer_hdr() {
    return (const struct syscallbuf_hdr*)syscallbuf_flush_buffer_array;
  }

  void setup_replay_one_trace_frame(Task* t);
  void advance_to_next_trace_frame(TraceFrame::Time stop_at_time);
  Completion emulate_signal_delivery(Task* oldtask, int sig,
                                     TraceFrame::Time stop_at_time);
  Completion try_one_trace_step(Task* t, RunCommand stepi,
                                TraceFrame::Time stop_at_time);
  Completion cont_syscall_boundary(Task* t, ExecOrEmulate emu,
                                   RunCommand stepi);
  Completion enter_syscall(Task* t, RunCommand stepi);
  Completion exit_syscall(Task* t, RunCommand stepi);
  Ticks get_ticks_slack(Task* t);
  void check_ticks_consistency(Task* t, const Event& ev);
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
  Completion emulate_deterministic_signal(Task* t, int sig, RunCommand stepi);
  Completion emulate_async_signal(Task* t, int sig, RunCommand stepi,
                                  Ticks ticks);
  Completion skip_desched_ioctl(Task* t, ReplayDeschedState* ds,
                                RunCommand stepi);
  void prepare_syscallbuf_records(Task* t);
  Completion flush_one_syscall(Task* t, RunCommand stepi);
  Completion flush_syscallbuf(Task* t, RunCommand stepi);
  Completion patch_next_syscall(Task* t, RunCommand stepi);
  bool is_last_interesting_task(Task* t);

  std::shared_ptr<EmuFs> emu_fs;
  Task* last_debugged_task;
  pid_t tgid_debugged;
  TraceReader trace_in;
  TraceFrame trace_frame;
  ReplayTraceStep current_step;
  CPUIDBugDetector cpuid_bug_detector;
  bool redirect_stdio_;
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
