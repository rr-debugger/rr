/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RECORD_SESSION_H_
#define RR_RECORD_SESSION_H_

#include "Session.h"

/** Encapsulates additional session state related to recording. */
class RecordSession : public Session {
public:
  typedef std::shared_ptr<RecordSession> shr_ptr;

  /**
   * Fork and exec the initial tracee task, and return it.
   */
  Task* create_task();

  TraceWriter& trace_writer() { return trace_out; }

  /**
   * Create a recording session for the initial exe image
   * |exe_path|.  (That argument is used to name the trace
   * directory.)
   */
  static shr_ptr create(const std::vector<std::string>& argv,
                        const std::vector<std::string>& envp,
                        const std::string& cwd, int bind_to_cpu);

  virtual RecordSession* as_record() override { return this; }

  virtual TraceStream& trace() override { return trace_out; }

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

  virtual void on_destroy(Task* t) override;

private:
  RecordSession(const std::vector<std::string>& argv,
                const std::vector<std::string>& envp, const std::string& cwd,
                int bind_to_cpu);

  virtual void on_create(Task* t) override;

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
};

#endif // RR_RECORD_SESSION_H_
