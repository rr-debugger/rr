/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rep_sched.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "replayer.h"

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
	assert(my_tid < MAX_TID_NUM);

	/* allocate data structure and initialize hashmap */
	struct context *ctx = sys_malloc(sizeof(struct context));
	memset(ctx, 0, sizeof(struct context));

	ctx->child_tid = my_tid;
	ctx->rec_tid = rec_tid;
	ctx->child_mem_fd = sys_open_child_mem(my_tid);

	//read_open_inst_dump(ctx);
	num_threads++;

	/* initializer replay counters */
	init_hpc(ctx);
	map[rec_tid] = ctx;
	return ctx;
}

struct context* rep_sched_get_thread()
{
	/* read the next trace entry */
	struct trace_frame trace;
	read_next_trace(&trace);
	/* find and update context */
	struct context *ctx = map[trace.tid];
	assert(ctx != NULL);

	/* copy the current trace */
	memcpy(&(ctx->trace), &trace, sizeof(struct trace_frame));

	/* subsequent reschedule-events of the same thread can be combined to a single event */
	/* XXX revisit this optimization ... it makes the lag to
	 * process debugger requests theoretically unbounded, but
	 * maybe we don't care in practice, or that lag is worth the
	 * gain from the optimization. */
	if (trace.stop_reason == USR_SCHED) {
		int combined = 0;
		struct trace_frame next_trace;

		peek_next_trace(&next_trace);
		uint64_t rbc = ctx->trace.rbc;
		while ((next_trace.stop_reason == USR_SCHED) && (next_trace.tid == ctx->rec_tid)) {
			rbc += next_trace.rbc;
			read_next_trace(&(ctx->trace));
			peek_next_trace(&next_trace);
			combined = 1;
		}

		if (combined) {
			ctx->trace.rbc = rbc;
		}
	}
	return ctx;
}

struct context* rep_sched_lookup_thread(pid_t rec_tid)
{
	assert(0 < rec_tid && rec_tid < MAX_TID_NUM);
	return map[rec_tid];
}

void rep_sched_deregister_thread(struct context **ctx_ptr)
{
	struct context * ctx = *ctx_ptr;
	destry_hpc(ctx);

	pid_t my_tid = ctx->child_tid;
	//sys_fclose(ctx->inst_dump);
	sys_close(ctx->child_mem_fd);

	map[my_tid] = NULL;
	num_threads--;
	assert(num_threads >= 0);

	/* detatch the child process*/
	sys_ptrace_detach(ctx->child_tid);
	int ret;
	do {
		ret = waitpid(ctx->child_tid, &(ctx->status), __WALL | __WCLONE);
		int event = GET_PTRACE_EVENT(ctx->status);
		/* Is this a bug in the ptrace impementation? After calling detach, we should not receive
		 * any ptrace signals. However, we still do in some cases... */
		if (event == 6) { // TODO: magic
			sys_ptrace_detach(ctx->child_tid);
		}
	} while (ret != -1);

	sys_free((void**) ctx_ptr);
}

void rep_sched_close()
{
	sys_free((void**) &map);
}

int rep_sched_get_num_threads()
{
	return num_threads;
}
