#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>

#include "recorder.h"
#include "rec_sched.h"

#include <sys/syscall.h>

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

static void set_switch_counter(struct context *last_ctx, struct context *ctx)
{
	assert(ctx != NULL);
	if (last_ctx == ctx) {
		ctx->switch_counter--;
	} else {
		ctx->switch_counter = MAX_SWITCH_COUNTER;
	}
}

/**
 * Retrieves a thread from the pool of active threads in a
 * round-robin fashion.
 */
struct context* get_active_thread(struct context *ctx)
{
	/* This maintains the order in which the threads are signaled to continue and
	 * when the the record is actually written
	 */

	if (ctx != 0) {
		if (!ctx->allow_ctx_switch) {
			return ctx;
		}

		/* switch to next thread if the thread reached the maximum number of RBCs */
		if (ctx->switch_counter < 0) {
			current_thread_ptr = list_next(current_thread_ptr);
			ctx->switch_counter = MAX_SWITCH_COUNTER;
		}
	}

	struct context *return_ctx;
	while (1) {
		/* check all threads again, do a full circle and wait */
		for (; !list_end(current_thread_ptr); current_thread_ptr = list_next(current_thread_ptr)) {
			return_ctx = (struct context *) list_data(current_thread_ptr);
			if (return_ctx != NULL) {
				if (return_ctx->exec_state == EXEC_STATE_IN_SYSCALL) {
					if (sys_waitpid_nonblock(return_ctx->child_tid, &(return_ctx->status)) != 0) {
						return_ctx->exec_state = EXEC_STATE_IN_SYSCALL_DONE;
						set_switch_counter(last_ctx, return_ctx);
						last_ctx = return_ctx;
						return return_ctx;
					}
					continue;
				}
				set_switch_counter(last_ctx, return_ctx);
				last_ctx = return_ctx;
				return return_ctx;
			}
		}
		current_thread_ptr = registered_threads;
	}

	return 0;
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
void rec_sched_register_thread(pid_t parent, pid_t child)
{
	assert(child > 0 && child < MAX_TID);

	if (!registered_threads)
		rec_sched_init();

	struct context *ctx = sys_malloc_zero(sizeof(struct context));

	ctx->exec_state = EXEC_STATE_START;
	ctx->status = 0;
	ctx->child_tid = child;
	ctx->child_mem_fd = sys_open_child_mem(child);

	sys_ptrace_setup(child);

	init_hpc(ctx);
	start_hpc(ctx, MAX_RECORD_INTERVAL);

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

	/* close file descriptor to child memory */
	sys_close(ctx->child_mem_fd);

	sys_ptrace_detatch(ctx->child_tid);

	/* make sure that the child has exited */

	int ret;
	do {
		ret = waitpid(ctx->child_tid, &ctx->status, __WALL | __WCLONE);
	} while (ret != -1);

	/* finally, free the memory */
	sys_free((void**) ctx_ptr);
}

