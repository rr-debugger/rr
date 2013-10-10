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

static RB_HEAD(task_tree, task) tasks = RB_INITIALIZER(&tasks);

RB_PROTOTYPE_STATIC(task_tree, task, entry, task_cmp)

static int num_threads;

static void add_task(struct task* t)
{
	RB_INSERT(task_tree, &tasks, t);
}

static struct task* find_task(pid_t tid)
{
	struct task search = { .rec_tid = tid };
	return RB_FIND(task_tree, &tasks, &search);
}

static void remove_task(struct task* t)
{
	RB_REMOVE(task_tree, &tasks, t);
}

struct task* rep_sched_register_thread(pid_t my_tid, pid_t rec_tid)
{
	assert(my_tid < MAX_TID_NUM);

	/* allocate data structure and initialize hashmap */
	struct task *t = sys_malloc(sizeof(struct task));
	memset(t, 0, sizeof(struct task));

	t->tid = my_tid;
	t->rec_tid = rec_tid;
	t->child_mem_fd = sys_open_child_mem(my_tid);
	push_placeholder_event(t);

	//read_open_inst_dump(t);
	num_threads++;

	/* initializer replay counters */
	init_hpc(t);
	add_task(t);
	return t;
}

struct task* rep_sched_get_thread()
{
	/* read the next trace entry */
	struct trace_frame trace;
	read_next_trace(&trace);
	/* find and update task */
	struct task *t = find_task(trace.tid);
	assert(t != NULL);

	/* copy the current trace */
	memcpy(&(t->trace), &trace, sizeof(struct trace_frame));

	/* subsequent reschedule-events of the same thread can be combined to a single event */
	/* XXX revisit this optimization ... it makes the lag to
	 * process debugger requests theoretically unbounded, but
	 * maybe we don't care in practice, or that lag is worth the
	 * gain from the optimization. */
	if (trace.stop_reason == USR_SCHED) {
		int combined = 0;
		struct trace_frame next_trace;

		peek_next_trace(&next_trace);
		uint64_t rbc = t->trace.rbc;
		while ((next_trace.stop_reason == USR_SCHED) && (next_trace.tid == t->rec_tid)) {
			rbc += next_trace.rbc;
			read_next_trace(&(t->trace));
			peek_next_trace(&next_trace);
			combined = 1;
		}

		if (combined) {
			t->trace.rbc = rbc;
		}
	}
	assert(get_global_time() == t->trace.global_time);
	return t;
}

struct task* rep_sched_lookup_thread(pid_t rec_tid)
{
	assert(0 < rec_tid && rec_tid < MAX_TID_NUM);
	return find_task(rec_tid);
}

void rep_sched_enumerate_tasks(pid_t** tids, size_t* len)
{
	pid_t* ts;
	struct task* t;
	int i;

	*len = num_threads;
	ts = *tids = sys_malloc(*len * sizeof(pid_t));
	i = 0;
	RB_FOREACH(t, task_tree, &tasks) {
		ts[i++] = t->rec_tid;
	}
	assert(i == num_threads);
}

void rep_sched_deregister_thread(struct task** t_ptr)
{
	struct task* t = *t_ptr;

	destroy_hpc(t);

	sys_close(t->child_mem_fd);

	remove_task(t);
	num_threads--;
	assert(num_threads >= 0);

	detach_and_reap(t);

	sys_free((void**)t_ptr);
}

int rep_sched_get_num_threads()
{
	return num_threads;
}

static int
task_cmp(void* pa, void* pb)
{
	struct task* a = (struct task*)pa;
	struct task* b = (struct task*)pb;
	return a->rec_tid - b->rec_tid;
}

RB_GENERATE_STATIC(task_tree, task, entry, task_cmp)
