/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

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
 */
Task* rec_sched_get_active_thread(RecordSession& session,
				  Task* t, int* by_waitpid);

void rec_sched_deregister_thread(Task** t);

#endif /* RR_REC_SCHED_H_ */
