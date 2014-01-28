/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Sched"
//#define MONITOR_UNSWITCHABLE_WAITS

#include "rec_sched.h"

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <algorithm>

#include "recorder.h"

#include "../share/config.h"
#include "../share/dbg.h"
#include "../share/sys.h"
#include "../share/task.h"

/**
 * The currently scheduled task. This may be NULL if the last scheduled task
 * has been destroyed.
 */
static Task* current;

static void note_switch(Task* prev_t, Task* t, int max_events)
{
	if (prev_t == t) {
		t->succ_event_counter++;
	} else {
		t->succ_event_counter = 0;
	}
}

static Task*
get_next_task_with_same_priority(Task* t)
{
	const Task::PrioritySet& tasks = Task::get_priority_set();
	auto it = tasks.find(std::make_pair(t->priority, t));
	assert(it != tasks.end());
	++it;
	if (it == tasks.end() || it->first != t->priority) {
		it = tasks.lower_bound(std::make_pair(t->priority, nullptr));
	}
	return it->second;
}

/**
 * Find the highest-priority task that is runnable. If the highest-priority
 * runnable task has the same priority as 'current', return 'current' or
 * the next runnable task after 'current' in round-robin order.
 * Sets 'by_waitpid' to true if we determined the task was runnable by
 * calling waitpid on it and observing a state change.
 */
static Task*
find_next_runnable_task(int* by_waitpid)
{
	*by_waitpid = 0;

	const Task::PrioritySet& tasks = Task::get_priority_set();
	// The outer loop has one iteration per unique priority value.
	// The inner loop iterates over all tasks with that priority.
	for (auto same_priority_start = tasks.begin();
		same_priority_start != tasks.end();) {
		int priority = same_priority_start->first;
		auto same_priority_end =
			tasks.lower_bound(std::make_pair(same_priority_start->first + 1, nullptr));

		auto begin_at = same_priority_start;
	        if (current && priority == current->priority) {
			begin_at = tasks.find(std::make_pair(priority, current));
		}

		auto task_iterator = begin_at;
		do {
			Task* t = task_iterator->second;
			pid_t tid = t->tid;

			if (t->unstable) {
				debug("  %d is unstable, going to waitpid(-1)", tid);
				return NULL;
			}

			if (!t->may_be_blocked()) {
				debug("  %d isn't blocked", tid);
				return t;
			}

			debug("  %d is blocked on %s, checking status ...", tid,
			      strevent(t->event));
			if (0 != sys_waitpid_nonblock(tid, &t->status)) {
				*by_waitpid = 1;
				debug("  ready with status 0x%x", t->status);
				return t;
			}
			debug("  still blocked");

			++task_iterator;
			if (task_iterator == same_priority_end) {
				task_iterator = same_priority_start;
			}
		} while (task_iterator != begin_at);

		same_priority_start = same_priority_end;
	}

	return NULL;
}

Task* rec_sched_get_active_thread(Task* t, int* by_waitpid)
{
	int max_events = rr_flags()->max_events;

	debug("Scheduling next task");

	*by_waitpid = 0;

	if (!current) {
		current = t;
	}
	assert(!t || t == current);

	if (current && !current->switchable) {
		debug("  (%d is un-switchable)", current->tid);
		if (current->may_be_blocked()) {
			debug("  and not runnable; waiting for state change");
			/* |current| is un-switchable, but not runnable in
			 * this state.  Wait for it to change state
			 * before "scheduling it", so avoid
			 * busy-waiting with our client. */
#ifdef MONITOR_UNSWITCHABLE_WAITS
			double start = now_sec(), wait_duration;
#endif
			if (!sys_waitpid(t->tid, &t->status)) {
				debug("  waitpid(%d) interrupted by EINTR",
				      t->tid);
				return nullptr;
			}
#ifdef MONITOR_UNSWITCHABLE_WAITS
			wait_duration = now_sec() - start;
			if (wait_duration >= 0.010) {
				warn("Waiting for unswitchable %s took %g ms",
				     strevent(current->event),
				     1000.0 * wait_duration);
			}
#endif
			*by_waitpid = 1;
			debug("  new status is 0x%x", current->status);
		}
		return current;
	}

	/* Prefer switching to the next task if the current one
	 * exceeded its event limit. */
	if (current && current->succ_event_counter > max_events) {
		debug("  previous task exceeded event limit, preferring next");
		current->succ_event_counter = 0;
		current = get_next_task_with_same_priority(current);
	}

	Task* next = find_next_runnable_task(by_waitpid);

	if (next) {
		debug("  selecting task %d", next->tid);
	} else {
		// All the tasks are blocked. Wait for the next one to
		// change state.
		int status;
		pid_t tid;

		debug("  all tasks blocked or some unstable, waiting for runnable (%d total)",
		      Task::count());
		while (-1 == (tid = waitpid(-1, &status,
					    __WALL | WSTOPPED | WUNTRACED))) {
			if (EINTR == errno) {
				debug("  waitpid(-1) interrupted by EINTR");
				return nullptr;
			}
			fatal("Failed to waitpid()");
		}
		debug("  %d changed status to 0x%x", tid, status);

		next = Task::find(tid);

		assert(next->unstable || next->may_be_blocked());
		next->status = status;
		*by_waitpid = 1;
	}

	note_switch(current, next, max_events);
	current = next;
	return current;
}

/**
 * Sends a SIGINT to all processes/threads.
 */
void rec_sched_exit_all()
{
	while (Task::count() > 0) {
		Task* t = Task::begin()->second;

		sys_kill(t->tid, SIGINT);
		rec_sched_deregister_thread(&t);
	}
}

/**
 * De-regsiter a thread and de-allocate all resources. This function
 * should be called when a thread exits.
 */
void rec_sched_deregister_thread(Task** t_ptr)
{
	Task* t = *t_ptr;

	if (t == current) {
		current = get_next_task_with_same_priority(t);
		if (t == current) {
			current = NULL;
		}
	}
	delete t;
	*t_ptr = NULL;
}
