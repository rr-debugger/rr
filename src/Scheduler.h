/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REC_SCHED_H_
#define RR_REC_SCHED_H_

#include <deque>
#include <set>

#include "Ticks.h"
#include "TraceFrame.h"
#include "util.h"

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
  /**
   * The following parameters define the default scheduling parameters.
   * The recorder scheduler basically works as follows
   *
   *  0. Find a task A with a pending event.
   *  1. If A was the last task scheduled, decrease its "max-event"
   *     counter.
   *  2. Program an HPC interrupt for A that will fire after "max-ticks"
   *     retired conditional branches (or so, it may not be precise).
   *  3. Resume the execution of A.
   *
   * The next thing that will occur is another scheduling event, after
   * which one of two things happens
   *
   *  0. Task A triggers a trace event in rr, which could be a signal,
   *     syscall entry/exit, HPC interrupt, ...
   *  1. Some other task triggers an event.
   *
   * And then we make another scheduling decision.
   *
   * Like in most task schedulers, there are conflicting goals to
   * balance.  Lower max-ticks / max-events generally makes the
   * application more "interactive", generally speaking lower latency.
   * (And wrt catching bugs, this setting generally creates more
   * opportunity for bugs to arise in multi-threaded/process
   * applications.)  This comes at the cost of more overhead from
   * scheduling and context switching.  Higher max-ticks / max-events
   * generally gives the application higher throughput.
   *
   * The rr scheduler is relatively dumb compared to modern OS
   * schedulers, but the default parameters are configured to achieve
   *
   *  o IO-heavy tasks are relatively quickly switched, in the hope this
   *    improves latency.
   *  o CPU-heavy tasks are given an O(10ms) timeslice before being
   *    switched.
   *  o Keep max number of HPC interrupts small to avoid overhead.
   *
   * In addition to all the aforementioned deficiencies, using retired
   * conditional branches to compute timeslices is quite crude, since
   * they don't correspond to any unit of time in general.  Hopefully
   * that can be improved, but empirical data from Firefox demonstrate,
   * surprisingly consistently, a distribution of insns/rcb massed
   * around 10.  Somewhat arbitrarily guessing ~4cycles/insn on average
   * (fair amount of pointer chasing), that implies
   *
   *  10ms = .01s = x rcb * (10insn / rcb) * (4cycle / insn) * (1s / 2e9cycle)
   *  x = 500000rcb / 10ms
   *
   * We'll arbitrarily decide to allow 10 max successive events for
   * latency reasons.  To try to keep overhead lower (since trace traps
   * are heavyweight), we'll give each task a relatively large 50ms
   * timeslice.  This works out to
   *
   *   50ms * (500000rcb / 10ms) / 10event = 250000 rcb / event
   */
  enum {
    DEFAULT_MAX_TICKS = 250000
  };
  enum {
    DEFAULT_MAX_EVENTS = 10
  };

  Scheduler(RecordSession& session)
      : session(session),
        current(nullptr),
        max_ticks_(DEFAULT_MAX_TICKS),
        max_events(DEFAULT_MAX_EVENTS) {}

  void set_max_ticks(Ticks max_ticks) { max_ticks_ = max_ticks; }
  Ticks max_ticks() const { return max_ticks_; }
  void set_max_events(TraceFrame::Time max_events) {
    this->max_events = max_events;
  }

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
  Task* get_next_thread(Task* t, Switchable switchable, bool* by_waitpid);

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

  Ticks max_ticks_;
  TraceFrame::Time max_events;
};

#endif /* RR_REC_SCHED_H_ */
