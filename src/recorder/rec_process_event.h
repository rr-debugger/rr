/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef PROCESS_SYSCALL_H_
#define PROCESS_SYSCALL_H_

#include "../share/types.h"
#include "../share/util.h"

/**
 * Prepare |t| to enter its current syscall event.  Return nonzero if
 * a context-switch is allowed for |t|, 0 if not.
 */
int rec_prepare_syscall(struct task* t);
/**
 * Prepare |t| for its current syscall event to be interrupted and
 * possibly restarted.
 */
void rec_prepare_restart_syscall(struct task* t);
/**
 * Restore any argument registers fudged for |t|'s current syscall and
 * store any nondeterministic outparam data.
 */
void rec_process_syscall(struct task* t);

#endif /* PROCESS_SYSCALL_H_ */
