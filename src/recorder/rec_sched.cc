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

#include "recorder.h"

#include "../share/config.h"
#include "../share/dbg.h"
#include "../share/sys.h"
#include "../share/task.h"

// The currently scheduled task.
static Task* current;

static void note_switch(Task* prev_t, Task* t, int max_events)
{
	if (prev_t == t) {
		t->succ_event_counter++;
	} else {
		t->succ_event_counter = 0;
	}
}

/**
 * Retrieves a thread from the pool of active threads in a
 * round-robin fashion.
 */
Task* rec_sched_get_active_thread(Task* t, int* by_waitpid)
{
	int max_events = rr_flags()->max_events;

	debug("Scheduling next task");

	*by_waitpid = 0;

	if (!current) {
		// This is the first scheduling request, so there
		// should only be one task.
		current = Task::begin()->second;
		assert(!t && 1 == Task::count());
	}

	if (t && !t->switchable) {
		debug("  (%d is un-switchable)", t->tid);
		if (t->may_be_blocked()) {
			debug("  and not runnable; waiting for state change");
			/* |t| is un-switchable, but not runnable in
			 * this state.  Wait for it to change state
			 * before "scheduling it", so avoid
			 * busy-waiting with our client. */
#ifdef MONITOR_UNSWITCHABLE_WAITS
			double start = now_sec(), wait_duration;
#endif

			sys_waitpid(t->tid, &t->status);

#ifdef MONITOR_UNSWITCHABLE_WAITS
			wait_duration = now_sec() - start;
			if (wait_duration >= 0.010) {
				warn("Waiting for unswitchable %s took %g ms",
				     strevent(t->event),
				     1000.0 * wait_duration);
			}
#endif
			*by_waitpid = 1;
			debug("  new status is 0x%x", t->status);
		}
		return t;
	}

	/* Prefer switching to the next task if the current one
	 * exceeded its event limit. */
	if (t && t->succ_event_counter > max_events) {
		debug("  previous task exceeded event limit, preferring next");
		current = current->next_roundrobin();
		t->succ_event_counter = 0;
	}

	// Go around the task list exactly one time looking for a
	// runnable thread.
	Task* next = NULL;
	// This helper is used to iterate over the list of tasks in
	// round-robin order.  XXX could C++-ify into real iterator...
	Task* it = current;
	do {
		next = it;
		pid_t tid = next->tid;

		if (next->unstable) {
			debug("  %d is unstable, going to waitpid(-1)", tid);
			next = NULL;
			break;
		}
		if (!next->may_be_blocked()) {
			debug("  %d isn't blocked, done", tid);
			break;
		}
		debug("  %d is blocked on %s, checking status ...", tid,
		      strevent(next->event));
		if (0 != sys_waitpid_nonblock(tid, &next->status)) {
			*by_waitpid = 1;
			debug("  ready with status 0x%x", next->status);
			break;
		}
		debug("  still blocked");
	} while (next = NULL, current != (it = it->next_roundrobin()));

	if (!next) {
		// All the tasks are blocked. Wait for the next one to
		// change state.
		int status;
		pid_t tid;

		debug("  all tasks blocked or some unstable, waiting for runnable (%d total)",
		      Task::count());
		while (-1 == (tid = waitpid(-1, &status,
					    __WALL | WSTOPPED | WUNTRACED))) {
			if (EINTR == errno) {
				debug("  waitpid() interrupted by EINTR");
				continue;
			}
			fatal("Failed to waitpid()");
		}
		debug("  %d changed state", tid);

		next = Task::find(tid);

		assert(next->unstable || next->may_be_blocked());
		next->status = status;
		*by_waitpid = 1;
	}

	current = next;
	note_switch(t, next, max_events);
	return next;
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
		current = t->next_roundrobin();
		if (t == current) {
			// We're destroying the last task and shutting
			// down.
			assert(Task::count() == 1);
			current = NULL;
		}
	}
	delete t;
	*t_ptr = NULL;
}
