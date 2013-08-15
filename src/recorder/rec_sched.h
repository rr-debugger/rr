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
struct task* rec_sched_get_active_thread(const struct flags* flags,
					    struct task* t,
					    int* by_waitpid);
void rec_sched_register_thread(const struct flags* flags,
			       pid_t parent, pid_t child);
void rec_sched_deregister_thread(struct task** t);
void rec_sched_exit_all();

#endif /* REC_SCHED_H_ */
