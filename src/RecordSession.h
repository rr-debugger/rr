/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_SESSION_H_
#define RR_RECORD_SESSION_H_

#include "Scheduler.h"
#include "Session.h"
#include "task.h"

enum ForceSyscall {
  DEFAULT_CONT = 0,
  FORCE_SYSCALL = 1
};

/** Encapsulates additional session state related to recording. */
class RecordSession : public Session {
public:
  typedef std::shared_ptr<RecordSession> shr_ptr;

  /**
   * Create a recording session for the initial exe image
   * |exe_path|.  (That argument is used to name the trace
   * directory.)
   */
  static shr_ptr create(const std::vector<std::string>& argv,
                        const std::vector<std::string>& envp,
                        const std::string& cwd);

  enum RecordStatus {
    // Some execution was recorded. record_step() can be called again.
    STEP_CONTINUE,
    // All tracees are dead. record_step() should not be called again.
    STEP_EXITED,
    // Initial exec of the tracee failed.
    STEP_EXEC_FAILED,
    // Required performance counter features not detected.
    STEP_PERF_COUNTERS_UNAVAILABLE
  };
  struct RecordResult {
    RecordStatus status;
    // When status == STEP_EXITED
    int exit_code;
  };
  /**
   * Record some tracee execution.
   * This may block. If blocking is interrupted by a signal, will return
   * STEP_CONTINUE.
   * Typically you'd call this in a loop until it returns something other than
   * STEP_CONTINUE.
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

private:
  RecordSession(const std::vector<std::string>& argv,
                const std::vector<std::string>& envp, const std::string& cwd,
                int bind_to_cpu);

  virtual void on_create(Task* t);

  void check_perf_counters_working(Task* t, RecordResult* step_result);
  void handle_ptrace_event(Task* t, ForceSyscall* force_cont);
  void runnable_state_changed(Task* t, RecordResult* step_result);

  TraceWriter trace_out;
  Scheduler scheduler_;
  Task* last_recorded_task;
  TaskGroup::shr_ptr initial_task_group;

  /* Nonzero when it's safe to deliver signals, namely, when the initial
   * tracee has exec()'d the tracee image.  Before then, the address
   * space layout will not be the same during replay as recording, so
   * replay won't be able to find the right execution point to deliver
   * the signal. */
  bool can_deliver_signals;
};

#endif // RR_RECORD_SESSION_H_
