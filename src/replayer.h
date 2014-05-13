/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_REPLAYER_H_
#define RR_REPLAYER_H_

#include "registers.h"
#include "types.h"
#include "util.h"

/**
 * Replay the trace.  argc, argv, and envp are this process's
 * parameters.
 */
void replay(int argc, char* argv[], char** envp);

/**
 * Open a temporary debugging connection for |t| and service requests
 * until the user quits or requests execution to resume.
 *
 * You probably don't want to use this directly; instead, use
 * |assert_exec()| from dbg.h.
 *
 * This function does not return.
 */
void emergency_debug(Task* t);

/**
 * Start a debugging connection for |t| and return when there are no
 * more requests to process (usually because the debugger detaches).
 *
 * Unlike |emergency_debug()|, this helper doesn't attempt to
 * determine whether blocking rr on a debugger connection might be a
 * bad idea.  It will always open the debug socket and block awaiting
 * a connection.
 */
void start_debug_server(Task* t);

/**
 * The state of a (dis)arm-desched-event ioctl that's being processed.
 */
enum RepDeschedType { DESCHED_ARM, DESCHED_DISARM };
enum RepDeschedState { DESCHED_ENTER, DESCHED_EXIT };
struct rep_desched_state {
	/* Is this an arm or disarm request? */
	RepDeschedType type;
	/* What's our next step to retire the ioctl? */
	RepDeschedState state;
};

/**
 * The state of a syscallbuf flush that's being processed.  Syscallbuf
 * flushes are an odd duck among the trace-step types (along with the
 * desched step above), because they must maintain extra state in
 * order to know which commands to issue when being resumed after an
 * interruption.  So the process of flushing the syscallbuf will
 * mutate this state in between attempts to retire the step.
 */
enum RepFlushState { FLUSH_START, FLUSH_ARM, FLUSH_ENTER, FLUSH_EXIT,
		     FLUSH_DISARM, FLUSH_DONE };
struct rep_flush_state {
	/* Nonzero when we need to write the syscallbuf data back to
	 * the child. */
	int need_buffer_restore;
	/* After the data is restored, the number of record bytes that
	 * still need to be flushed. */
	size_t num_rec_bytes_remaining;
	/* The syscallbuf record that was saved to trace.  This is
	 * what we'll use to restore |child_rec| below. */
	const struct syscallbuf_record* rec_rec;
	/* Pointer to the tracee's next syscallbuf record to replay. */
	struct syscallbuf_record* child_rec;
	/* The next step to take. */
	RepFlushState state;
	/* Track the state of retiring desched arm/disarm ioctls, when
	 * necessary. */
	struct rep_desched_state desched;
};

/**
 * Describes the next step to be taken in order to replay a trace
 * frame.
 */
enum RepTraceStepType {
	TSTEP_NONE,

	/* Frame has been replayed, done. */
	TSTEP_RETIRE,

	/* Enter/exit a syscall.  |syscall| describe what should be
	 * done at entry/exit. */
	TSTEP_ENTER_SYSCALL,
	TSTEP_EXIT_SYSCALL,

	/* Advance to the deterministic signal |signo|. */
	TSTEP_DETERMINISTIC_SIGNAL,

	/* Advance until |target.rcb| have been retired and then
	 * |target.ip| is reached.  Deliver |target.signo| after that
	 * if it's nonzero. */
	TSTEP_PROGRAM_ASYNC_SIGNAL_INTERRUPT,

	/* Replay the upcoming buffered syscalls.  |flush| tracks the
	 * replay state.*/
	TSTEP_FLUSH_SYSCALLBUF,

	/* Emulate arming or disarming the desched event.  |desched|
	 * tracks the replay state. */
	TSTEP_DESCHED,
};
struct rep_trace_step {
	RepTraceStepType action;

	union {
		struct {
			/* The syscall number we expect to
			 * enter/exit. */
			int no;
			/* Is the kernel entry and exit for this
			 * syscall emulated, that is, not executed? */
			int emu;
			/* The number of outparam arguments that are
			 * set from what was recorded. */
			ssize_t num_emu_args;
			/* Nonzero if the return from the syscall
			 * should be emulated.  |emu| implies this. */
			int emu_ret;
		} syscall;

		int signo;

		struct {
			int64_t rcb;
			int signo;
		} target;

		struct rep_flush_state flush;

		struct rep_desched_state desched;
	};
};

#endif /* RR_REPLAYER_H_ */
