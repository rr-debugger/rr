/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REP_PROCESS_EVENT_H_
#define RR_REP_PROCESS_EVENT_H_

#include "TraceStream.h"

class Task;
struct ReplayTraceStep;

/**
 * Call this when |t| has just entered a syscall.  At this point, data
 * saved at |rec_before_record_syscall_entry()| can be restored.
 */
void rep_after_enter_syscall(Task* t, int syscallno);

/* Process pending syscall. Call this when |t| is about to enter or exit
 * a syscall. */
void rep_process_syscall(Task* t, ReplayTraceStep* step);

/**
 * |t| is at a "write" syscall.  If the recorded write was to STDOUT
 * or STDERR, then also write the output to the current STDOUT/STDERR
 * (if the user wishes).
 *
 * NB: this doesn't bother to check for writes to the actual
 * STDOUT/STDERR /files/, just the fd numbers.  We don't record file
 * information.  That means output written to a dup of STDOUT will not
 * be replayed by this helper.  This could maybe be a todo.
 */
void rep_maybe_replay_stdio_write(Task* t);

#endif /* RR_REP_PROCESS_EVENT_H_ */
