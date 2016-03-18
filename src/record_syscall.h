/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROCESS_SYSCALL_H_
#define RR_PROCESS_SYSCALL_H_

#include "task.h"

/**
 * Prepare |t| to enter its current syscall event.  Return ALLOW_SWITCH if
 * a context-switch is allowed for |t|, PREVENT_SWITCH if not.
 */
Switchable rec_prepare_syscall(Task* t);

/**
 * Prepare |t| for its current syscall event to be interrupted and
 * possibly restarted.
 */
void rec_prepare_restart_syscall(Task* t);

/**
 * Inside a fork/clone syscall, notify that the new task created is new_task.
 */
void rec_set_syscall_new_task(Task* t, Task* new_task);

/**
 * Restore any argument registers fudged for |t|'s current syscall and
 * store any nondeterministic outparam data.
 */
void rec_process_syscall(Task* t);

#endif /* RR_PROCESS_SYSCALL_H_ */
