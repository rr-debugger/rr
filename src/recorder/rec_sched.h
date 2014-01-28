/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef REC_SCHED_H_
#define REC_SCHED_H_

class Task;

/**
 * Given |flags| and the previously-scheduled task |t|, return a new
 * runnable task (which may be |t|).
 *
 * The returned task is guaranteed to either have already been
 * runnable, or have been made runnable by a waitpid status change (in
 * which case, *by_waitpid will be nonzero.)
 */
Task* rec_sched_get_active_thread(Task* t, int* by_waitpid);

void rec_sched_deregister_thread(Task** t);
void rec_sched_exit_all(void);

#endif /* REC_SCHED_H_ */
