/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_SESSION_H_
#define RR_RECORD_SESSION_H_

#include <string>
#include <vector>

#include "Scheduler.h"
#include "SeccompFilterRewriter.h"
#include "Session.h"
#include "task.h"
#include "TraceFrame.h"

/** Encapsulates additional session state related to recording. */
class RecordSession : public Session {
public:
  typedef std::shared_ptr<RecordSession> shr_ptr;

  /**
   * Create a recording session for the initial command line |argv|.
   */
  enum SyscallBuffering { ENABLE_SYSCALL_BUF, DISABLE_SYSCALL_BUF };
  enum BindCPU { BIND_CPU, UNBOUND_CPU };
  enum Chaos { ENABLE_CHAOS, DISABLE_CHAOS };
  static shr_ptr create(
      const std::vector<std::string>& argv,
      const std::vector<std::string>& extra_env = std::vector<std::string>(),
      SyscallBuffering syscallbuf = ENABLE_SYSCALL_BUF,
      BindCPU bind_cpu = BIND_CPU, Chaos chaos = DISABLE_CHAOS);

  bool use_syscall_buffer() const { return use_syscall_buffer_; }
  void set_ignore_sig(int ignore_sig) { this->ignore_sig = ignore_sig; }
  int get_ignore_sig() const { return ignore_sig; }

  enum RecordStatus {
    // Some execution was recorded. record_step() can be called again.
    STEP_CONTINUE,
    // All tracees are dead. record_step() should not be called again.
    STEP_EXITED,
    // Spawning the initial tracee failed. An error message will be in
    // failure_message.
    STEP_SPAWN_FAILED
  };
  struct RecordResult {
    RecordStatus status;
    // When status == STEP_EXITED
    int exit_code;
    // When status == STEP_SPAWN_FAILED
    std::string failure_message;
  };
  /**
   * Record some tracee execution.
   * This may block. If blocking is interrupted by a signal, will return
   * STEP_CONTINUE.
   * Typically you'd call this in a loop until it returns something other than
   * STEP_CONTINUE.
   * Note that when this returns, some tasks may be running (not in a ptrace-
   * stop). In particular, up to one task may be executing user code and any
   * number of tasks may be blocked in syscalls.
   */
  RecordResult record_step();

  /**
   * Flush buffers and write a termination record to the trace. Don't call
   * record_step() after this.
   */
  void terminate_recording();

  virtual RecordSession* as_record() { return this; }

  TraceWriter& trace_writer() { return trace_out; }

  virtual void on_destroy(Task* t);

  Scheduler& scheduler() { return scheduler_; }

  SeccompFilterRewriter& seccomp_filter_rewriter() {
    return seccomp_filter_rewriter_;
  }

  enum ContinueType { DONT_CONTINUE = 0, CONTINUE, CONTINUE_SYSCALL };

  struct StepState {
    // Continue with this continuation type.
    ContinueType continue_type;
    StepState(ContinueType continue_type) : continue_type(continue_type) {}
  };

  void set_enable_chaos(bool enable_chaos) {
    this->enable_chaos_ = enable_chaos;
  }
  bool enable_chaos() { return enable_chaos_; }

  void set_wait_for_all(bool wait_for_all) {
    this->wait_for_all_ = wait_for_all;
  }

private:
  RecordSession(const std::vector<std::string>& argv,
                const std::vector<std::string>& envp, const std::string& cwd,
                SyscallBuffering syscallbuf, BindCPU bind_cpu, Chaos chaos);

  virtual void on_create(Task* t);

  void check_perf_counters_working(Task* t, RecordResult* step_result);
  bool handle_ptrace_event(Task* t, StepState* step_state);
  bool handle_signal_event(Task* t, StepState* step_state);
  void runnable_state_changed(Task* t, RecordResult* step_result,
                              bool can_consume_wait_status);
  void signal_state_changed(Task* t, StepState* step_state);
  void syscall_state_changed(Task* t, StepState* step_state);
  void desched_state_changed(Task* t);
  bool prepare_to_inject_signal(Task* t, StepState* step_state);
  void task_continue(const StepState& step_state);
  bool can_end();

  TraceWriter trace_out;
  Scheduler scheduler_;
  TaskGroup::shr_ptr initial_task_group;
  SeccompFilterRewriter seccomp_filter_rewriter_;

  int ignore_sig;
  Switchable last_task_switchable;
  bool use_syscall_buffer_;

  /**
   * When true, try to increase the probability of finding bugs.
   */
  bool enable_chaos_;
  /**
   * When true, wait for all tracees to exit before finishing recording.
   */
  bool wait_for_all_;
};

#endif // RR_RECORD_SESSION_H_
