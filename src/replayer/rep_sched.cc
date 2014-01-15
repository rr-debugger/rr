/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rep_sched.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "replayer.h"

#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/sys.h"
#include "../share/task.h"
#include "../share/trace.h"
#include "../share/util.h"

Task* rep_sched_register_thread(pid_t my_tid, pid_t rec_tid)
{
	/* allocate data structure and initialize hashmap */
	Task* t = new Task(my_tid, rec_tid);

	t->tid = my_tid;
	t->rec_tid = rec_tid;
	push_placeholder_event(t);
	t->child_mem_fd = sys_open_child_mem(t);

	/* initializer replay counters */
	init_hpc(t);
	return t;
}

Task* rep_sched_get_thread()
{
	/* read the next trace entry */
	struct trace_frame trace;
	read_next_trace(&trace);
	/* find and update task */
	Task *t = Task::find(trace.tid);
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

void rep_sched_enumerate_tasks(pid_t** tids, size_t* len)
{
	pid_t* ts;

	*len = Task::count();
	ts = *tids = (pid_t*)malloc(*len * sizeof(pid_t));
	int i = 0;
	for (Task::Map::const_iterator it = Task::begin(); it != Task::end();
	     ++it) {
		Task* t = it->second;
		ts[i++] = t->rec_tid;
	}
	assert(i == Task::count());
}

void rep_sched_deregister_thread(Task** t_ptr)
{
	Task* t = *t_ptr;

	destroy_hpc(t);

	sys_close(t->child_mem_fd);

	detach_and_reap(t);

	delete t;
	*t_ptr = NULL;
}
