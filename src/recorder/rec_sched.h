/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef REC_SCHED_H_
#define REC_SCHED_H_

#include <sys/types.h>

/* TODO remove this limitation by storing the tasks in a map.
 * Refactor the replayer map into a common tasks.{c,h} helper in
 * share/.  */
/* TODO: should check kernel.pid_max at runtime.  */
#define MAX_TID	(1 << 16)

struct task;
struct flags;

int rec_sched_get_num_threads();
/**
 * Given |flags| and the previously-scheduled task |t|, return a new
 * runnable task (which may be |t|).
 *
 * The returned task is guaranteed to either have already been
 * runnable, or have been made runnable by a waitpid status change (in
 * which case, *by_waitpid will be nonzero.)
 */
struct task* rec_sched_get_active_thread(struct task* t, int* by_waitpid);

/**
 * An invariant of rr scheduling is that all process status changes
 * happen as a result of rr resuming the execution of a task.  This is
 * required to keep tracees in known states, preventing events from
 * happening "behind rr's back".  However, sometimes this is
 * unavoidable; one case is delivering some kinds of death signals.
 * When that situation occurs, notify the scheduler by calling this
 * function: the effect is that the scheduler will always use
 * |waitpid(-1)| to schedule tasks, thereby assuming nothing about
 * tasks' statuses.
 *
 * When stability returns, call |rec_set_tasks_stable()|.
 *
 * TODO: this can fail with multiple task groups.
 */
void rec_sched_set_tasks_unstable();
void rec_sched_set_tasks_stable();

/**
 * Register the new OS task |child|, created by |parent|.  |parent|
 * may be 0 for the first registered task, but must be a registered
 * task for all subsequent calls.  |share_sighandlers| is nonzero if
 * |parent| and |child| will share the same sighandlers table, and
 * zero if |child| will get a copy of |parent|'s table.
 */
enum { COPY_SIGHANDLERS = 0, SHARE_SIGHANDLERS = 1 };
void rec_sched_register_thread(pid_t parent, pid_t child,
			       int share_sighandlers);
void rec_sched_deregister_thread(struct task** t);
void rec_sched_exit_all();

#endif /* REC_SCHED_H_ */
