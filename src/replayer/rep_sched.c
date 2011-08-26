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
	struct context *context = sys_malloc(sizeof(struct context));
	memset(context,0,sizeof(struct context));

	context->child_tid = my_tid;
	context->rec_tid = rec_tid;

	read_open_inst_dump(context);
	num_threads++;

	/* initializer replay counters */
	init_hpc(context);

	map[rec_tid] = context;
	return context;
}

struct context* rep_sched_get_thread()
{
	/* read the next trace entry */
	struct trace trace;
	read_next_trace(&trace);

	/* find and upadte context */
	struct context *ctx = map[trace.tid];
	if (ctx->pending_sig != 0) {
		assert(trace.stop_reason >= 0);
	}

	memcpy(&(ctx->trace), &trace, sizeof(struct trace));

	return ctx;
}

void rep_sched_deregister_thread(struct context *ctx)
{
	destry_hpc(ctx);

	/* detatch the child process*/
	sys_ptrace_detatch(ctx->child_tid);

	pid_t my_tid = ctx->child_tid;
	sys_fclose(ctx->inst_dump);

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
