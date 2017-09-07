/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROCESS_SYSCALL_H_
#define RR_PROCESS_SYSCALL_H_

#include "util.h"

namespace rr {

class RecordTask;

/**
 * Prepare |t| to enter its current syscall event.  Return ALLOW_SWITCH if
 * a context-switch is allowed for |t|, PREVENT_SWITCH if not.
 */
Switchable rec_prepare_syscall(RecordTask* t);

/**
 * Any prepared syscall is not going to happen (because it was aborted by
 * tracee seccomp filter). Cancel any preparation work.
 */
void rec_abort_prepared_syscall(RecordTask* t);

/**
 * Prepare |t| for its current syscall event to be interrupted and
 * possibly restarted.
 */
void rec_prepare_restart_syscall(RecordTask* t);

/**
 * Restore any argument registers fudged for |t|'s current syscall and
 * store any nondeterministic outparam data.
 */
void rec_process_syscall(RecordTask* t);

} // namespace rr

#endif /* RR_PROCESS_SYSCALL_H_ */
