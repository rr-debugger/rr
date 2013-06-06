/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef REPLAYER_H_
#define REPLAYER_H_

#include "../share/types.h"
#include "../share/util.h"

void replay(struct flags rr_flags);

/**
 * Open a temporary debugging connection for |ctx| and service
 * requests until the user quits or requests execution to resume.  Use
 * this when a target enters an illegal state and can't continue, for
 * example
 *
 *  if (recorded_state != replay_state) {
 *	 log_err("Bad state ...");
 *	 emergency_debug(tid);
 *  }
 *
 * This function does not return.
 */
void emergency_debug(struct context* ctx);

/**
 * Describes the next step to be taken in order to replay a trace
 * frame.
 */
struct rep_trace_step {
	enum {
		TSTEP_UNKNOWN,

		/* Frame has been replayed, done. */
		TSTEP_RETIRE,

		/* Enter/exit a syscall.  |params.syscall| describe
		 * what should be done at entry/exit. */
		TSTEP_ENTER_SYSCALL,
		TSTEP_EXIT_SYSCALL,

		/* Advance to the synchronous signal
		 * |params.signo|. */
		TSTEP_SYNCHRONOUS_SIGNAL,

		/* Advance until |params.interrupt.target_rcb| have
		 * been retired and then |params.interrupt.target_ip|
		 * is reached. */
		TSTEP_PROGRAM_INTERRUPT,
	} action;

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
			size_t num_emu_args;
			/* Nonzero if the return from the syscall
			 * should be emulated.  |emu| implies this. */
			int emu_ret;
		} syscall;

		int signo;

		struct {
			uint64_t target_rcb;
			void* target_ip;
		} slice;
	} params;
};

#endif /* REPLAYER_H_ */
