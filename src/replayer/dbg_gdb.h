/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef DBG_GDB_H_
#define DBG_GDB_H_

#include <stddef.h>
#include <sys/types.h>

struct dbg_context;

/**
 * Descriptor for a target task.  This is following gdb convention; on
 * linux, the tid is sufficient to identify a target.
 *
 * For both fields, -1 means "all", and 0 means "any".
 *
 * TODO support gdb "multiprocess".
 */
struct dbg_thread_id {
	pid_t pid;
	pid_t tid;
};

/**
 * These requests are made by the debugger host and honored in proxy
 * by rr, the target.
 */
struct dbg_request {
	enum { 
		DREQ_NONE = 0,

		/* None of these requests have parameters. */
		DREQ_GET_CURRENT_THREAD,
		DREQ_GET_OFFSETS,
		DREQ_GET_REGS,
		DREQ_GET_STOP_REASON,

		/* Uses params.mem. */
		DREQ_GET_MEM,

		/* Uses params.reg. */
		DREQ_GET_REG,

		/* These use params.resume. */
		DREQ_CONTINUE,
		DREQ_STEP,

		/* No parameters. */
		DREQ_INTERRUPT,

		/* TODO */
		DREQ_GET_THREAD_LIST,

		DREQ_REMOVE_BREAKPOINT,
		DREQ_SET_BREAKPOINT,
		DREQ_SET_CURRENT_THREAD,

		DREQ_DETACH,
	} type;

	struct dbg_thread_id target;

	union {
		struct {
			long addr;
			size_t len;
		} mem;

		long reg;

		struct {
			/* Resume from this address, or 0 to resume from
			 * same address. */
			long addr;
			/* Resume with this signal, or 0 for no signal. */
			char signum;
		} resume;
	} params;
};

/**
 * Return nonzero if |req| requires that program execution be resumed
 * in some way.
 */
int dbg_is_resume_request(const struct dbg_request* req);

/**
 * Wait for exactly one gdb host to connect to this remote target.
 *
 * This function is infallible: either it will return a valid
 * debugging context, or it won't return.
 * 
 * TODO currently, calling this function more than once results in
 * undefined behavior.
 */
struct dbg_context* dbg_await_client_connection();

/**
 * Return the current request made by the debugger host, that needs to
 * be satisfied.  This function will block until either there's a
 * debugger host request that needs a response, or until a request is
 * made to resume execution of the target.  In the latter case,
 * calling this function multiple times will return an appropriate
 * resume request each time (see above).
 *
 * The target should peek at the debugger request in between execution
 * steps.  A new request may need to be serviced.
 */
struct dbg_request dbg_get_request(struct dbg_context* dbg);

/**
 * Notify the host that a resume request has "finished", i.e., the
 * target has stopped executing for some reason.
 */
void dbg_notify_stop(struct dbg_context* dbg/*, TODO */);

/**
 * Reply to the DREQ_GET_CURRENT_THREAD request.
 */
void dbg_reply_get_current_thread(struct dbg_context* dbg,
				  struct dbg_thread_id thread);

/**
 * Reply to the DREQ_GET_MEM request.
 */
void dbg_reply_get_mem(struct dbg_context* dbg/*, TODO */);

/**
 * Reply to the DREQ_GET_OFFSETS request.
 */
void dbg_reply_get_offsets(struct dbg_context* dbg/*, TODO */);

/**
 * Reply to the DREQ_GET_REGS request.
 */
void dbg_reply_get_regs(struct dbg_context* dbg/*, TODO */);

/**
 * Reply to the DREQ_GET_REG request.
 */
void dbg_reply_get_reg(struct dbg_context* dbg, long value);

/**
 * Reply to the DREQ_GET_STOP_REASON request.
 */
void dbg_reply_get_stop_reason(struct dbg_context* dbg/*, TODO */);

/**
 * Destroy a gdb debugging context created by
 * |dbg_await_client_connection()|.  It's legal to pass a null |*dbg|.
 * The passed-in outparam is nulled on return.
 */
void dbg_destroy_context(struct dbg_context** dbg);

#endif /* DBG_GDB_G_ */
