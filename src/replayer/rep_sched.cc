/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rep_sched.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <map>

#include "replayer.h"

#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/sys.h"
#include "../share/task.h"
#include "../share/trace.h"
#include "../share/util.h"

#define MAX_TID_NUM 100000

using namespace std;

typedef map<pid_t, Task*> TaskMap;
static TaskMap tasks;

static void add_task(Task* t)
{
	tasks[t->rec_tid] = t;
}

static Task* find_task(pid_t tid)
{
	TaskMap::const_iterator it = tasks.find(tid);
	return tasks.end() != it ? it->second : NULL;
}

static void remove_task(Task* t)
{
	assert(find_task(t->rec_tid));
	tasks.erase(t->rec_tid);
}

Task* rep_sched_register_thread(pid_t my_tid, pid_t rec_tid)
{
	assert(my_tid < MAX_TID_NUM);

	/* allocate data structure and initialize hashmap */
	Task* t = new Task(my_tid, rec_tid);

	t->tid = my_tid;
	t->rec_tid = rec_tid;
	push_placeholder_event(t);
	t->child_mem_fd = sys_open_child_mem(t);

	/* initializer replay counters */
	init_hpc(t);
	add_task(t);
	return t;
}

Task* rep_sched_get_thread()
{
	/* read the next trace entry */
	struct trace_frame trace;
	read_next_trace(&trace);
	/* find and update task */
	Task *t = find_task(trace.tid);
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

Task* rep_sched_lookup_thread(pid_t rec_tid)
{
	assert(0 < rec_tid && rec_tid < MAX_TID_NUM);
	return find_task(rec_tid);
}

void rep_sched_enumerate_tasks(pid_t** tids, size_t* len)
{
	pid_t* ts;

	*len = tasks.size();
	ts = *tids = (pid_t*)malloc(*len * sizeof(pid_t));
	int i = 0;
	for (TaskMap::const_iterator it = tasks.begin(); it != tasks.end();
	     ++it) {
		Task* t = it->second;
		ts[i++] = t->rec_tid;
	}
	assert(size_t(i) == tasks.size());
}

void rep_sched_deregister_thread(Task** t_ptr)
{
	Task* t = *t_ptr;

	destroy_hpc(t);

	sys_close(t->child_mem_fd);

	remove_task(t);

	detach_and_reap(t);

	delete t;
	*t_ptr = NULL;
}

int rep_sched_get_num_threads()
{
	return tasks.size();
}
