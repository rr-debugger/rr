/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "recorder.h"
#include "rec_sched.h"

#include <sys/syscall.h>

#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/list.h"
#include "../share/sys.h"
#include "../share/config.h"

#define DELAY_COUNTER_MAX 10

static struct list *tid_to_node[MAX_TID] = {NULL};
static struct list *registered_threads = NULL;
static struct list *current_thread_ptr = NULL;
static int num_active_threads = 0;
static struct context * last_ctx;

static void rec_sched_init()
{
	current_thread_ptr = registered_threads = list_new();
}

static void set_switch_counter(struct context *last_ctx, struct context *ctx,
			       int max_events)
{
	assert(ctx != NULL);
	if (last_ctx == ctx) {
		ctx->switch_counter--;
	} else {
		ctx->switch_counter = max_events;
	}
}

/**
 * Retrieves a thread from the pool of active threads in a
 * round-robin fashion.
 */
struct context* get_active_thread(const struct flags* flags,
				  struct context* ctx)
{
	struct context* next_ctx = NULL;
	int max_events = flags->max_events;
	struct list* node = current_thread_ptr;

	debug("Scheduling next task");

	if (ctx && !ctx->allow_ctx_switch) {
		debug("  (previous task was uninterruptible)");
		return ctx;
	}

	/* Prefer switching to the next task if |ctx| exceeded its
	 * event limit. */
	if (ctx && ctx->switch_counter < 0) {
		debug("  previous task exceeded event limit, preferring next");
		node = current_thread_ptr = list_next(current_thread_ptr);
		ctx->switch_counter = max_events;
	}

	/* Go around the task list exactly one time looking for a
	 * runnable thread. */
	do {
		if (list_end(node)) {
			/* Wrap around the end of the list. */
			node = registered_threads;
		}
		next_ctx = (struct context*)list_data(node);
		/* XXX when can next_ctx be null? */
		if (next_ctx
		    && next_ctx->exec_state != EXEC_STATE_IN_SYSCALL) {
			/* |next_ctx| is non-null and not blocked on a
			 * syscall; that's what we're looking for. */
			debug("  %d isn't blocked, done", next_ctx->child_tid);
			break;
		}
		if (next_ctx) {
			pid_t tid = next_ctx->child_tid;
			/* We don't know yet whether |next_ctx| is
			 * runnable; check quickly.  We do this check
			 * to preserve scheduler fairness: if we
			 * skipped this check, we would starve tasks
			 * that enter syscalls.  */
			debug("  %d is blocked, checking status ...", tid);
			if (sys_waitpid_nonblock(tid, &(next_ctx->status))) {
				debug("  ready!");
				next_ctx->exec_state = EXEC_STATE_IN_SYSCALL_DONE;
				break;
			}
			/* |next_ctx| isn't ready, try to find another
			 * thread.*/
			debug("  still blocked");
			next_ctx = NULL;
		}
		node = list_next(node);
	} while (node != current_thread_ptr);

	if (!next_ctx) {
		/* All the tasks are blocked.  Wait for the next one
		 * to change state. */
		int status;
		pid_t tid;

		debug("  all tasks blocked, waiting for runnable (%d total)",
		      num_active_threads);
		while (-1 == (tid = waitpid(-1, &status,
					    __WALL | WSTOPPED | WUNTRACED))) {
			if (EINTR == errno) {
				debug("  waitpid() interrupted by EINTR");
				continue;
			}
			fatal("Failed to waitpid()");
		}
		debug("  %d changed state", tid);

		next_ctx = list_data(tid_to_node[tid]);

		assert(next_ctx->exec_state == EXEC_STATE_IN_SYSCALL);

		next_ctx->status = status;
		next_ctx->exec_state = EXEC_STATE_IN_SYSCALL_DONE;
	}

	current_thread_ptr = node;
	/* XXX shouldn't the next two statements be reversed? */
	set_switch_counter(last_ctx, next_ctx, max_events);
	last_ctx = ctx;
	return next_ctx;
}

/**
 * Sends a SIGINT to all processes/threads.
 */
void rec_sched_exit_all()
{
	/* workaround if this function is called in replay mode
	 * TODO: fix this after merging the command line parameter handling
	 */
	if (registered_threads) {
		struct list * thread_ptr = 0;
		for (thread_ptr = registered_threads; !list_end(thread_ptr); thread_ptr = list_next(thread_ptr)) {
			struct context *thread = (struct context *) list_data(thread_ptr);
			if (thread != NULL ) {
				int tid = thread->child_tid;
				if (tid != EMPTY) {
					sys_kill(tid, SIGINT);
					tid_to_node[tid] = NULL;
				}
			}
		}
		sys_free((void **)&registered_threads);
	}
}

int rec_sched_get_num_threads()
{
	return num_active_threads;
}

/**
 * Registers a new thread to the runtime system. This includes
 * initialization of the hardware performance counters
 */
void rec_sched_register_thread(const struct flags* flags,
			       pid_t parent, pid_t child)
{
	assert(child > 0 && child < MAX_TID);

	if (!registered_threads)
		rec_sched_init();

	struct context *ctx = sys_malloc_zero(sizeof(struct context));

	ctx->exec_state = EXEC_STATE_START;
	ctx->status = 0;
	ctx->rec_tid = ctx->child_tid = child;
	ctx->child_mem_fd = sys_open_child_mem(child);
	if (parent) {
		struct context* parent_ctx = (struct context *)list_data(tid_to_node[parent]);
		ctx->syscallbuf_lib_start = parent_ctx->syscallbuf_lib_start;
		ctx->syscallbuf_lib_end = parent_ctx->syscallbuf_lib_end;
	}
	/* These will be initialized when the syscall buffer is. */
	ctx->desched_fd = ctx->desched_fd_child = -1;

	sys_ptrace_setup(child);

	init_hpc(ctx);
	start_hpc(ctx, flags->max_rbc);

	registered_threads = list_push_front(registered_threads, ctx);
	num_active_threads++;

	tid_to_node[child] = registered_threads;
}

/**
 * De-regsiter a thread and de-allocate all resources. This function
 * should be called when a thread exits.
 */
void rec_sched_deregister_thread(struct context **ctx_ptr)
{
	struct context *ctx = *ctx_ptr;
	struct list * node = tid_to_node[ctx->child_tid], *next = list_next(node);
	if (!list_end(next)) {
		pid_t next_tid = ((struct context *)list_data(next))->child_tid;
		tid_to_node[next_tid] = node;
	}
	list_remove(node); // this copied node over next and frees next!
	tid_to_node[ctx->child_tid] = NULL;
	num_active_threads--;
	assert(num_active_threads >= 0);

	/* delete all counter data */
	cleanup_hpc(ctx);

	sys_close(ctx->child_mem_fd);
	close(ctx->desched_fd);

	sys_ptrace_detach(ctx->child_tid);

	/* finally, free the memory */
	sys_free((void**) ctx_ptr);
}
