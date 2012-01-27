#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "replayer.h"
#include "read_trace.h"
#include "../share/trace.h"
#include "../share/hpc.h"
#include "../share/sys.h"
#include "../share/util.h"


#define MAX_TID_NUM 100000

static struct context** map;
static int num_threads;

void rep_sched_init()
{
	map = sys_malloc(MAX_TID_NUM * sizeof(struct context));
}

struct context* rep_sched_register_thread(pid_t my_tid, pid_t rec_tid)
{
	assert (my_tid < MAX_TID_NUM);

	/* allocate data structure and initialize hashmap */
	struct context *ctx = sys_malloc(sizeof(struct context));
	memset(ctx,0,sizeof(struct context));

	ctx->child_tid = my_tid;
	ctx->rec_tid = rec_tid;
	ctx->child_mem_fd = sys_open_child_mem(my_tid);


	read_open_inst_dump(ctx);
	num_threads++;

	/* initializer replay counters */
	init_hpc(ctx);
	map[rec_tid] = ctx;
	return ctx;
}

struct context* rep_sched_get_thread()
{
	/* read the next trace entry */
	struct trace trace;
	read_next_trace(&trace);

	/* find and update context */
	struct context *ctx = map[trace.tid];
	assert(ctx != NULL);
	if (ctx->child_sig != 0) {
		assert(trace.stop_reason >= 0);
	}

	/* read the current trace */
	memcpy(&(ctx->trace), &trace, sizeof(struct trace));


	/* subsequent reschedule-events of the same thread can be combined to a single event */
	struct trace next_trace;
	peek_next_trace(&next_trace);
	uint64_t rbc_up = ctx->trace.rbc_up;
	//printf("this stop reason: %d    this tid: %d    next_tid: %d\n",ctx->trace.stop_reason, ctx->child_tid, next_trace.tid);
	while ((ctx->trace.stop_reason == USR_SCHED) && (next_trace.tid == ctx->rec_tid)) {
		rbc_up += next_trace.rbc_up;
		read_next_trace(&(ctx->trace));
		peek_next_trace(&next_trace);
		//printf("subsumed\n");
	}

	if (ctx->trace.stop_reason == USR_SCHED) {
		ctx->trace.rbc_up = rbc_up;
	}

	return ctx;
}

void rep_sched_deregister_thread(struct context *ctx)
{
	destry_hpc(ctx);

	/* detatch the child process*/
	sys_ptrace_detatch(ctx->child_tid);

	pid_t my_tid = ctx->child_tid;
	sys_fclose(ctx->inst_dump);
	sys_close(ctx->child_mem_fd);

	map[my_tid] = NULL;
	num_threads--;
	assert(num_threads >= 0);


	sys_free((void**) &ctx);
}

void rep_sched_close()
{
	sys_free((void**) &map);
}

int rep_sched_get_num_threads()
{
	return num_threads;
}
