/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_SESSION_H_
#define RR_RECORD_SESSION_H_

#include "Session.h"

#include "task.h"

/** Encapsulates additional session state related to recording. */
class RecordSession : public Session {
public:
  typedef std::shared_ptr<RecordSession> shr_ptr;
  // Tasks sorted by priority.
  typedef std::set<std::pair<int, Task*> > TaskPrioritySet;
  typedef std::deque<Task*> TaskQueue;

  /**
   * Create a recording session for the initial exe image
   * |exe_path|.  (That argument is used to name the trace
   * directory.)
   */
  static shr_ptr create(const std::vector<std::string>& argv,
                        const std::vector<std::string>& envp,
                        const std::string& cwd, int bind_to_cpu);

  enum StepResultStatus {
    // Some execution was recorded. record_step() can be called again.
    STEP_CONTINUE,
    // All tracees are dead. record_step() should not be called again.
    STEP_EXITED,
    // Initial exec of the tracee failed.
    STEP_EXEC_FAILED,
    // Required performance counter features not detected.
    STEP_PERF_COUNTERS_UNAVAILABLE
  };

  struct StepResult {
    StepResultStatus status;
    // When status == STEP_EXITED
    int exit_code;
  };

  /**
   * Record some tracee execution.
   * This may block. If blocking is interrupted by a signal, will return
   * STEP_CONTINUE.
   */
  StepResult record_step();

  /**
   * Flush buffers and write a termination record to the trace. Don't call
   * record_step() after this.
   */
  void terminate_recording();

  TraceWriter& trace_writer() { return trace_out; }

  virtual RecordSession* as_record() { return this; }

  virtual TraceStream& trace() { return trace_out; }

  /** Get tasks organized by priority. */
  const TaskPrioritySet& tasks_by_priority() { return task_priority_set; }

  /**
   * Set the priority of |t| to |value| and update related
   * state.
   */
  void update_task_priority(Task* t, int value);

  /**
   * Do one round of round-robin scheduling if we're not already doing one.
   * If we start round-robin scheduling now, make last_task the last
   * task to be scheduled.
   * If the task_round_robin_queue is empty this moves all tasks into it,
   * putting last_task last.
   */
  void schedule_one_round_robin(Task* last_task);

  /**
   * Returns the first task in the round-robin queue or null if it's empty.
   */
  Task* get_next_round_robin_task();
  /**
   * Removes a task from the front of the round-robin queue.
   */
  void remove_round_robin_task();

  virtual void on_destroy(Task* t);

private:
  RecordSession(const std::vector<std::string>& argv,
                const std::vector<std::string>& envp, const std::string& cwd,
                int bind_to_cpu);

  virtual void on_create(Task* t);

  void check_perf_counters_working(Task* t, StepResult* step_result);
  void handle_ptrace_event(Task* t);
  void runnable_state_changed(Task* t, StepResult* step_result);

  TraceWriter trace_out;

  /**
   * Every task of this session is either in task_priority_set
   * (when in_round_robin_queue is false), or in task_round_robin_queue
   * (when in_round_robin_queue is true).
   *
   * task_priority_set is a set of pairs of (task->priority, task). This
   * lets us efficiently iterate over the tasks with a given priority, or
   * all tasks in priority order.
   */
  TaskPrioritySet task_priority_set;
  TaskQueue task_round_robin_queue;

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
