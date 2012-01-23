#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>

#include "recorder.h"
#include "rec_sched.h"
#include "write_trace.h"

#include "../share/hpc.h"
#include "../share/sys.h"
#include "../share/config.h"

/* we could use a linked-list instead */
static struct context* registered_threads[NUM_MAX_THREADS];
static int num_active_threads;

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
	}

	static int i = -1;
	i++;

	/* check from current index(i) till the end of the array */
	for (; i < NUM_MAX_THREADS; i++) {
		if (registered_threads[i] != NULL) {
			return registered_threads[i];
		}
	}

	/* check all threads again */
	for (i = 0; i < NUM_MAX_THREADS; i++) {
		if (registered_threads[i] != NULL) {
			return registered_threads[i];
		}
	}

	/* we must not come here */
	assert(1==0);
	return NULL;
}

/**
 * Sends a SIGINT to all processes/threads.
 */
void rec_sched_exit_all()
{
	int i;
	for (i = 0; i < NUM_MAX_THREADS; i++) {
		if (registered_threads[i] != NULL) {
			int tid = registered_threads[i]->child_tid;
			if (tid != EMPTY) {
				sys_kill(tid, SIGINT);
			}
		}
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
	assert (child > 0 && child < MAX_TID);

	int hash = HASH(child);
	assert(registered_threads[hash] == 0);
	struct context* ctx = sys_malloc_zero(sizeof(struct context));

	ctx->exec_state = EXEC_STATE_START;
	ctx->status = 0;
	ctx->child_tid = child;
	ctx->child_mem_fd = sys_open_child_mem(child);

	write_open_inst_dump(ctx);
	sys_ptrace_setup(child);


	init_hpc(ctx);
	start_hpc(ctx,MAX_RECORD_INTERVAL);

	registered_threads[hash] = ctx;
	num_active_threads++;
}

/**
 * De-regsiter a thread and de-allocate all resources. This function
 * should be called when a thread exits.
 */
void rec_sched_deregister_thread(struct context **ctx_ptr)
{
	struct context *ctx = *ctx_ptr;
	int hash = HASH(ctx->child_tid);

	registered_threads[hash] = 0;
	num_active_threads--;
	assert(num_active_threads >= 0);

	/* close the inst_dump file */
	sys_fclose(ctx->inst_dump);

	/* delete all counter data */
	destry_hpc(ctx);

	/* close file descriptor to child memory */
	sys_close(ctx->child_mem_fd);

	sys_ptrace_detatch(ctx->child_tid);


	/* finally, free the memory */
	sys_free((void**) ctx_ptr);
}

void rec_sched_set_exec_state(int tid, int state)
{
	int hash = HASH(tid);
	assert(registered_threads[hash]->child_tid == GET_TID(tid));

	registered_threads[hash]->exec_state = state;
}

