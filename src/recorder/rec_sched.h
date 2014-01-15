/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef REC_SCHED_H_
#define REC_SCHED_H_

#include <sys/types.h>

/* TODO remove this limitation by storing the tasks in a map.
 * Refactor the replayer map into a common tasks.{c,h} helper in
 * share/.  */
/* TODO: should check kernel.pid_max at runtime.  */
#define MAX_TID	(1 << 16)

class Task;
struct flags;

/**
 * Given |flags| and the previously-scheduled task |t|, return a new
 * runnable task (which may be |t|).
 *
 * The returned task is guaranteed to either have already been
 * runnable, or have been made runnable by a waitpid status change (in
 * which case, *by_waitpid will be nonzero.)
 */
Task* rec_sched_get_active_thread(Task* t, int* by_waitpid);

/**
 * Register the new OS task |child|, created by |parent|.  |parent|
 * may be 0 for the first registered task, but must be a registered
 * task for all subsequent calls.  |flags| is a bitset determining
 * which resources |parent| and |child| will share.
 *
 * If |flags & SHARE_SIGHANDLERS|, the child will get a reference to
 * the parent's sighandlers table.  Otherwise it gets a copy.
 *
 * If |flags & SHARE_TASK_GROUP|, the child will join the parent's
 * task group.  Otherwise it becomes its own new thread group.
 */
enum { DEFAULT_COPY = 0, SHARE_SIGHANDLERS = 0x1, SHARE_TASK_GROUP = 0x2 };
Task* rec_sched_register_thread(pid_t parent, pid_t child, int flags);
void rec_sched_deregister_thread(Task** t);
void rec_sched_exit_all(void);

#endif /* REC_SCHED_H_ */
