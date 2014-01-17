/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef REP_PROCESS_EVENT_H_
#define REP_PROCESS_EVENT_H_

class Task;
struct rep_trace_step;

/* |redirect_stdio| is nonzero if output written to stdout/stderr
 * during recording should be tee'd during replay, zero otherwise. */
void rep_process_syscall(Task* t, struct rep_trace_step* step);

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

namespace EmuFs {
/**
 * Collect emulated files that aren't referenced by tracees.  Call
 * this only when a tracee (possibly shared) file table has been
 * destroyed.  All other gc triggers are handled internally.
 */
void gc();
}

#endif /* REP_PROCESS_EVENT_H_ */
