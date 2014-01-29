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

using namespace std;

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
	const Task::MapByPriority& map = Task::get_map_by_priority();
	auto map_it = map.find(t->priority);
	auto task_list = map_it->second;
	auto it = find(task_list.begin(), task_list.end(), t);
	assert(it != task_list.end());
	++it;
	if (it == task_list.end()) {
		it = task_list.begin();
	}
	return *it;
}

static Task*
find_next_runnable_task(int* by_waitpid)
{
	*by_waitpid = 0;

	const Task::MapByPriority& map = Task::get_map_by_priority();
	for (auto outer_iterator = map.begin(); outer_iterator != map.end();
	     ++outer_iterator) {
	        const list<Task*>& task_list = outer_iterator->second;
	        int priority = outer_iterator->first;
	        list<Task*>::const_iterator begin;
	        if (current && priority == current->priority) {
			begin = find(task_list.begin(), task_list.end(), current);
	        } else {
			// Just iterate through all of them
			begin = task_list.begin();
	        }

		auto inner_iterator = begin;
		do {
			Task* next = *inner_iterator;
			pid_t tid = next->tid;

			if (next->unstable) {
				debug("  %d is unstable, going to waitpid(-1)", tid);
				return NULL;
			}

			if (!next->may_be_blocked()) {
				debug("  %d isn't blocked", tid);
				return next;
			}

			debug("  %d is blocked on %s, checking status ...", tid,
			      strevent(next->event));
			if (0 != sys_waitpid_nonblock(tid, &next->status)) {
				*by_waitpid = 1;
				debug("  ready with status 0x%x", next->status);
				return next;
			}
			debug("  still blocked");

			++inner_iterator;
			if (inner_iterator == task_list.end()) {
				inner_iterator = task_list.begin();
			}
		} while (inner_iterator != begin);
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
