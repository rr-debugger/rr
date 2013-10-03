/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef DBG_GDB_H_
#define DBG_GDB_H_

#include <stddef.h>
#include <sys/types.h>

#include "../share/types.h"

struct dbg_context;

/**
 * Descriptor for a target task.
 *
 * TODO support gdb "multiprocess".
 */
typedef pid_t dbg_threadid_t;

/**
 * This is gdb's view of the register file.  The ordering must be the
 * same as in the gdb sources.
 */
typedef enum {
	DREG_EAX, DREG_ECX, DREG_EDX, DREG_EBX,
	DREG_ESP, DREG_EBP, DREG_ESI, DREG_EDI,
	DREG_EIP, DREG_EFLAGS,
	DREG_CS, DREG_SS, DREG_DS, DREG_ES, DREG_FS, DREG_GS,
	DREG_ST0,
	/* Last register we can find in user_regs_struct (except for
	 * orig_eax). */
	DREG_NUM_USER_REGS = DREG_GS + 1,
	DREG_MXCSR = 40,
	DREG_YMM0H,
	DREG_YMM7H = DREG_YMM0H + 7,
	DREG_NUM_AVX = DREG_YMM0H + 1,
	DREG_ORIG_EAX = DREG_NUM_AVX,
	DREG_NUM_LINUX_I386 = DREG_ORIG_EAX + 1
} dbg_register;

/**
 * Represents a possibly-undefined register value.  |defined| is
 * nonzero if |value| is well defined.
 */
typedef struct dbg_regvalue {
	int defined;
	long value;
} dbg_regvalue_t;

/**
 * Represents the register file, indexed by |dbg_register| values
 * above.
 */
struct dbg_regfile {
	dbg_regvalue_t regs[DREG_NUM_LINUX_I386];
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
		DREQ_GET_THREAD_LIST,

		/* These use params.target. */
		DREQ_GET_IS_THREAD_ALIVE,
		DREQ_SET_CONTINUE_THREAD,
		DREQ_SET_QUERY_THREAD,

		/* These use params.mem. */
		DREQ_GET_MEM,
		DREQ_REMOVE_SW_BREAK,
		DREQ_WATCH_FIRST = DREQ_REMOVE_SW_BREAK,
		DREQ_REMOVE_HW_BREAK,
		DREQ_REMOVE_RD_WATCH,
		DREQ_REMOVE_WR_WATCH,
		DREQ_REMOVE_RDWR_WATCH,
		DREQ_SET_SW_BREAK,
		DREQ_SET_HW_BREAK,
		DREQ_SET_RD_WATCH,
		DREQ_SET_WR_WATCH,
		DREQ_SET_RDWR_WATCH,
		DREQ_WATCH_LAST = DREQ_SET_RDWR_WATCH,

		/* Uses params.reg. */
		DREQ_GET_REG,

		/* No parameters. */
		DREQ_CONTINUE,
		DREQ_INTERRUPT,
		DREQ_STEP,
	} type;

	dbg_threadid_t target;

	union {
		struct {
			void* addr;
			size_t len;
		} mem;

		dbg_register reg;
	};
};

/**
 * Return nonzero if |req| requires that program execution be resumed
 * in some way.
 */
int dbg_is_resume_request(const struct dbg_request* req);

/**
 * Wait for exactly one gdb host to connect to this remote target on
 * IP address |addr|, port |port|.  If |probe| is nonzero, a unique
 * port based on |start_port| will be searched for.  Otherwise, if
 * |port| is already bound, this function will fail.
 *
 * This function is infallible: either it will return a valid
 * debugging context, or it won't return.
 */
enum { DONT_PROBE = 0, PROBE_PORT };
struct dbg_context* dbg_await_client_connection(const char* addr,
						unsigned short port,
						int probe);

/**
 * Call this when the target of |req| is needed to fulfill the
 * request, but the target is dead.  This situation is a symptom of a
 * gdb or rr bug.
 */
void dbg_notify_no_such_thread(struct dbg_context* dbg,
			       const struct dbg_request* req);

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
 * Notify the host that this process has exited with |code|.
 */
void dbg_notify_exit_code(struct dbg_context* dbg, int code);

/**
 * Notify the host that this process has exited from |sig|.
 */
void dbg_notify_exit_signal(struct dbg_context* dbg, int sig);

/**
 * Notify the host that a resume request has "finished", i.e., the
 * target has stopped executing for some reason.  |sig| is the signal
 * that stopped execution, or 0 if execution stopped otherwise.
 */
void dbg_notify_stop(struct dbg_context* dbg, dbg_threadid_t which, int sig);

/**
 * Tell the host that |thread| is the current thread.
 */
void dbg_reply_get_current_thread(struct dbg_context* dbg,
				  dbg_threadid_t thread);

/**
 * |alive| is nonzero if the requested thread is alive, zero if dead.
 */
void dbg_reply_get_is_thread_alive(struct dbg_context* dbg, int alive);

/**
 * |ok| is nonzero if req->target can be selected, zero otherwise.
 */
void dbg_reply_select_thread(struct dbg_context* dbg, int ok);

/**
 * The first |len| bytes of the request were read into |mem|.  |len|
 * must be less than or equal to the length of the request.
 */
void dbg_reply_get_mem(struct dbg_context* dbg, const byte* mem, size_t len);

/**
 * Reply to the DREQ_GET_OFFSETS request.
 */
void dbg_reply_get_offsets(struct dbg_context* dbg/*, TODO */);

/**
 * Send |value| back to the debugger host.  |value| may be undefined.
 */
void dbg_reply_get_reg(struct dbg_context* dbg, dbg_regvalue_t value);

/**
 * Send |file| back to the debugger host.  |file| may contain
 * undefined register values.
 */
void dbg_reply_get_regs(struct dbg_context* dbg,
			const struct dbg_regfile* file);

/**
 * Reply to the DREQ_GET_STOP_REASON request.
 */
void dbg_reply_get_stop_reason(struct dbg_context* dbg,
			       dbg_threadid_t which, int sig);

/**
 * |threads| contains the list of live threads, of which there are
 * |len|.
 */
void dbg_reply_get_thread_list(struct dbg_context* dbg,
			       const dbg_threadid_t* threads, size_t len);

/**
 * |code| is 0 if the request was successfully applied, nonzero if
 * not.
 */
void dbg_reply_watchpoint_request(struct dbg_context* dbg, int code);

/**
 * Destroy a gdb debugging context created by
 * |dbg_await_client_connection()|.  It's legal to pass a null |*dbg|.
 * The passed-in outparam is nulled on return.
 */
void dbg_destroy_context(struct dbg_context** dbg);

#endif /* DBG_GDB_G_ */
