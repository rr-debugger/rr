/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROCESS_SYSCALL_H_
#define RR_PROCESS_SYSCALL_H_

class Task;

/**
 * Call this just before the recorder is going to store a
 * syscall-entry event.  If any data needs to be saved at syscall
 * entry, do it now.
 */
void rec_before_record_syscall_entry(Task* t, int syscallno);

/**
 * Prepare |t| to enter its current syscall event.  Return ALLOW_SWITCH if
 * a context-switch is allowed for |t|, PREVENT_SWITCH if not.
 *
 * Set |*kernel_sync_addr| to non-NULL to force waiting on that memory
 * cell in the child's address space to become |sync_val|.  This is an
 * overly general mechanism that's used for FUTEX_LOCK_PI.  If you're
 * not FUTEX_LOCK_PI, you probably shouldn't be using this.
 */
int rec_prepare_syscall(Task* t);

/**
 * Prepare |t| for its current syscall event to be interrupted and
 * possibly restarted.
 */
void rec_prepare_restart_syscall(Task* t);

/**
 * Restore any argument registers fudged for |t|'s current syscall and
 * store any nondeterministic outparam data.
 */
void rec_process_syscall(Task* t);

#endif /* RR_PROCESS_SYSCALL_H_ */
