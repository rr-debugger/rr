/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REC_SCHED_H_
#define RR_REC_SCHED_H_

#include <deque>
#include <set>

class RecordSession;
class Task;

/**
 * Overview of rr scheduling:
 *
 * rr honours priorities set by setpriority(2) --- even in situations where the
 * kernel doesn't, e.g. when a non-privileged task tries to increase its
 * priority. Normally rr honors priorities strictly by scheduling the highest
 * priority runnable task; tasks with equal priorities are scheduled in
 * round-robin fashion. Strict priority scheduling helps find bugs due to
 * starvation.
 *
 * When a task calls sched_yield we temporarily switch to a completely
 * fair scheduler that ignores priorities. All tasks are placed on a queue
 * and while the queue is non-empty we take the next task from the queue and
 * run it for a quantum if it's runnable. We do this because tasks calling
 * sched_yield are often expecting some kind of fair scheduling and may deadlock
 * (e.g. trying to acquire a spinlock) if some other tasks don't get a chance
 * to run.
 */
class Scheduler {
public:
  Scheduler(RecordSession& session) : session(session), current(nullptr) {}

  /**
   * Given a previously-scheduled task |t|, return a new runnable task (which
   * may be |t|).
   *
   * The returned task is guaranteed to either have already been
   * runnable, or have been made runnable by a waitpid status change (in
   * which case, *by_waitpid will be nonzero.)
   *
   * Return nullptr if an interrupt occurred while waiting on a tracee.
   */
  Task* get_next_thread(Task* t, bool* by_waitpid);

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

  void on_create(Task* t);
  /**
   * De-register a thread. This function should be called when a thread exits.
   */
  void on_destroy(Task* t);

private:
  // Tasks sorted by priority.
  typedef std::set<std::pair<int, Task*> > TaskPrioritySet;
  typedef std::deque<Task*> TaskQueue;

  /**
   * Pull a task from the round-robin queue if available. Otherwise,
   * find the highest-priority task that is runnable. If the highest-priority
   * runnable task has the same priority as 'current', return 'current' or
   * the next runnable task after 'current' in round-robin order.
   * Sets 'by_waitpid' to true if we determined the task was runnable by
   * calling waitpid on it and observing a state change.
   */
  Task* find_next_runnable_task(bool* by_waitpid);
  /**
   * Returns the first task in the round-robin queue or null if it's empty.
   */
  Task* get_next_round_robin_task();
  /**
   * Removes a task from the front of the round-robin queue.
   */
  void remove_round_robin_task();
  Task* get_next_task_with_same_priority(Task* t);

  RecordSession& session;

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

  /**
   * The currently scheduled task. This may be nullptr if the last scheduled
   * task
   * has been destroyed.
   */
  Task* current;
};

#endif /* RR_REC_SCHED_H_ */
