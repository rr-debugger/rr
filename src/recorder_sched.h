/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REC_SCHED_H_
#define RR_REC_SCHED_H_

class RecordSession;
class Task;

/**
 * Given |flags| and the previously-scheduled task |t|, return a new
 * runnable task (which may be |t|).
 *
 * The returned task is guaranteed to either have already been
 * runnable, or have been made runnable by a waitpid status change (in
 * which case, *by_waitpid will be nonzero.)
 *
 * Return nullptr if an interrupt occurred while waiting on a tracee.
 *
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
Task* rec_sched_get_active_thread(RecordSession& session, Task* t,
                                  int* by_waitpid);

void rec_sched_deregister_thread(Task** t);

#endif /* RR_REC_SCHED_H_ */
