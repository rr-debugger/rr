/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rep_sched.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "replayer.h"

#include "../external/tree.h"
#include "../share/trace.h"
#include "../share/hpc.h"
#include "../share/sys.h"
#include "../share/task.h"
#include "../share/util.h"

#define MAX_TID_NUM 100000

static RB_HEAD(context_tree, context) tasks = RB_INITIALIZER(&tasks);

RB_PROTOTYPE_STATIC(context_tree, context, entry, context_cmp)

static int num_threads;

static void add_task(struct context* ctx)
{
	RB_INSERT(context_tree, &tasks, ctx);
}

static struct context* find_task(pid_t tid)
{
	struct context search = { .rec_tid = tid };
	return RB_FIND(context_tree, &tasks, &search);
}

static void remove_task(struct context* ctx)
{
	RB_REMOVE(context_tree, &tasks, ctx);
}

struct context* rep_sched_register_thread(pid_t my_tid, pid_t rec_tid)
{
	assert(my_tid < MAX_TID_NUM);

	/* allocate data structure and initialize hashmap */
	struct context *ctx = sys_malloc(sizeof(struct context));
	memset(ctx, 0, sizeof(struct context));

	ctx->tid = my_tid;
	ctx->rec_tid = rec_tid;
	ctx->child_mem_fd = sys_open_child_mem(my_tid);

	//read_open_inst_dump(ctx);
	num_threads++;

	/* initializer replay counters */
	init_hpc(ctx);
	add_task(ctx);
	return ctx;
}

struct context* rep_sched_get_thread()
{
	/* read the next trace entry */
	struct trace_frame trace;
	read_next_trace(&trace);
	/* find and update context */
	struct context *ctx = find_task(trace.tid);
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
	return find_task(rec_tid);
}

void rep_sched_enumerate_tasks(pid_t** tids, size_t* len)
{
	pid_t* ts;
	struct context* ctx;
	int i;

	*len = num_threads;
	ts = *tids = sys_malloc(*len * sizeof(pid_t));
	i = 0;
	RB_FOREACH(ctx, context_tree, &tasks) {
		ts[i++] = ctx->rec_tid;
	}
	assert(i == num_threads);
}

void rep_sched_deregister_thread(struct context **ctx_ptr)
{
	struct context * ctx = *ctx_ptr;
	destry_hpc(ctx);

	//sys_fclose(ctx->inst_dump);
	sys_close(ctx->child_mem_fd);

	remove_task(ctx);
	num_threads--;
	assert(num_threads >= 0);

	/* detatch the child process*/
	sys_ptrace_detach(ctx->tid);

	sys_free((void**) ctx_ptr);
}

int rep_sched_get_num_threads()
{
	return num_threads;
}

static int
context_cmp(void* pa, void* pb)
{
	struct context* a = (struct context*)pa;
	struct context* b = (struct context*)pb;
	return a->rec_tid - b->rec_tid;
}

RB_GENERATE_STATIC(context_tree, context, entry, context_cmp)
