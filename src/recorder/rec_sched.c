/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Sched"

#include "rec_sched.h"

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "recorder.h"

#include "../share/config.h"
#include "../share/dbg.h"
#include "../share/hpc.h"
#include "../share/sys.h"
#include "../share/task.h"

struct tasklist_entry {
	struct task t;
	CIRCLEQ_ENTRY(tasklist_entry) entries;
};

CIRCLEQ_HEAD(tasklist, tasklist_entry) head = CIRCLEQ_HEAD_INITIALIZER(head);

static struct tasklist_entry* tid_to_entry[MAX_TID];
static struct tasklist_entry* current_entry;
static int num_active_threads;

static struct tasklist_entry* get_entry(pid_t tid)
{
	return tid_to_entry[tid];
}

static struct task* get_task(pid_t tid)
{
	struct tasklist_entry* entry = get_entry(tid);
	return entry ? &entry->t : NULL;
}

static struct tasklist_entry* next_entry(struct tasklist_entry* elt)
{
	return CIRCLEQ_LOOP_NEXT(&head, elt, entries);
}

static void note_switch(struct task* prev_t, struct task* t,
			int max_events)
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
struct task* rec_sched_get_active_thread(struct task* t, int* by_waitpid)
{
	int max_events = rr_flags()->max_events;
	struct tasklist_entry* entry = current_entry;
	struct task* next_t = NULL;

	debug("Scheduling next task");

	*by_waitpid = 0;

	if (!entry) {
		entry = current_entry = CIRCLEQ_FIRST(&head);
	}

	if (t && !t->switchable) {
		debug("  (%d is un-switchable)", t->tid);
		if (task_may_be_blocked(t)) {
			debug("  and not runnable; waiting for state change");
			/* |t| is un-switchable, but not runnable in
			 * this state.  Wait for it to change state
			 * before "scheduling it", so avoid
			 * busy-waiting with our client.
			 *
			 * TODO: warn about long waits here,
			 * indicating that the syscall should be made
			 * switchable if possible. */
			sys_waitpid(t->tid, &t->status);
			*by_waitpid = 1;
			debug("  new status is 0x%x", t->status);
		}
		return t;
	}

	/* Prefer switching to the next task if the current one
	 * exceeded its event limit. */
	if (t && t->succ_event_counter > max_events) {
		debug("  previous task exceeded event limit, preferring next");
		entry = current_entry = next_entry(entry);
		t->succ_event_counter = 0;
	}

	/* Go around the task list exactly one time looking for a
	 * runnable thread. */
	do {
		pid_t tid;

		next_t = &entry->t;
		tid = next_t->tid;
		if (!task_may_be_blocked(next_t)) {
			debug("  %d isn't blocked, done", tid);
			break;
		}
		debug("  %d is blocked on %s, checking status ...", tid,
		      strevent(next_t->event));
		if (0 != sys_waitpid_nonblock(tid, &next_t->status)) {
			*by_waitpid = 1;
			debug("  ready!");
			break;
		}
		debug("  still blocked");
		next_t = NULL;
		entry = next_entry(entry);
	} while (entry != current_entry);

	if (!next_t) {
		/* All the tasks are blocked. Wait for the next one to
		 * change state. */
		int status;
		pid_t tid;

		debug("  all tasks blocked, waiting for runnable (%d total)",
		      num_active_threads);
		while (-1 == (tid = waitpid(-1, &status,
					    __WALL | WSTOPPED | WUNTRACED))) {
			if (EINTR == errno) {
				debug("  waitpid() interrupted by EINTR");
				continue;
			}
			fatal("Failed to waitpid()");
		}
		debug("  %d changed state", tid);

		entry = get_entry(tid);
		next_t = &entry->t;

		assert(task_may_be_blocked(next_t));
		next_t->status = status;
		*by_waitpid = 1;
	}

	current_entry = entry;
	note_switch(t, next_t, max_events);
	return next_t;
}

/**
 * Sends a SIGINT to all processes/threads.
 */
void rec_sched_exit_all()
{
	while (!CIRCLEQ_EMPTY(&head)) {
		struct tasklist_entry* entry = CIRCLEQ_FIRST(&head);
		struct task* t = &entry->t;

		sys_kill(t->tid, SIGINT);
		rec_sched_deregister_thread(&t);
	}
}

int rec_sched_get_num_threads()
{
	return num_active_threads;
}

/**
 * Registers a new thread to the runtime system. This includes
 * initialization of the hardware performance counters
 */
void rec_sched_register_thread(pid_t parent, pid_t child,
			       int share_sighandlers)
{
	struct tasklist_entry* entry = sys_malloc_zero(sizeof(*entry));
	struct task* t = &entry->t;

	assert(child > 0 && child < MAX_TID);

	t->status = 0;
	t->rec_tid = t->tid = child;
	t->child_mem_fd = sys_open_child_mem(child);
	if (parent) {
		struct task* parent_t = get_task(parent);
		struct sighandlers* parent_handlers = parent_t->sighandlers;

		t->syscallbuf_lib_start = parent_t->syscallbuf_lib_start;
		t->syscallbuf_lib_end = parent_t->syscallbuf_lib_end;
		t->sighandlers = share_sighandlers ?
				 sighandlers_ref(parent_handlers) :
				 sighandlers_copy(parent_handlers);
	} else {
		/* After the first task is forked, we always need to
		 * know the parent in order to initialize some task
		 * state. */
		static int is_first_task = 1;
		assert(is_first_task);
		is_first_task = 0;
		/* The very first task we fork inherits our
		 * sighandlers (which should all be default at this
		 * point, but ...).  From there on, new tasks will
		 * transitively inherit from this first task.  */
		t->sighandlers = sighandlers_new();
		sighandlers_init_from_current_process(t->sighandlers);
	}
	/* These will be initialized when the syscall buffer is. */
	t->desched_fd = t->desched_fd_child = -1;

	sys_ptrace_setup(child);

	init_hpc(t);
	start_hpc(t, rr_flags()->max_rbc);

	CIRCLEQ_INSERT_TAIL(&head, entry, entries);
	num_active_threads++;

	tid_to_entry[child] = entry;
}

/**
 * De-regsiter a thread and de-allocate all resources. This function
 * should be called when a thread exits.
 */
void rec_sched_deregister_thread(struct task** t_ptr)
{
	struct task* t = *t_ptr;
	pid_t tid = t->tid;
	struct tasklist_entry* entry = get_entry(tid);

	if (entry == current_entry) {
		current_entry = next_entry(entry);
		if (entry == current_entry) {
			assert(num_active_threads == 1);
			current_entry = NULL;
		}
	}

	/* We expect tasks to usually exit by a call to exit() or
	 * exit_group(), so it's not helpful to warn about that. */
	if (FIXEDSTACK_DEPTH(&t->pending_events) > 1
	    || (t->ev && !(t->ev->type == EV_SYSCALL
			   && (SYS_exit == t->ev->syscall.no
			       || SYS_exit_group == t->ev->syscall.no)))) {
		log_warn("%d still has pending events.  From top down:",
			 t->tid);
		log_pending_events(t);
	}

	CIRCLEQ_REMOVE(&head, entry, entries);
	tid_to_entry[tid] = NULL;
	num_active_threads--;
	assert(num_active_threads >= 0);

	/* delete all counter data */
	cleanup_hpc(t);

	sys_close(t->child_mem_fd);
	close(t->desched_fd);

	sys_ptrace_detach(tid);

	/* finally, free the memory */
	sighandlers_unref(&t->sighandlers);
	sys_free((void**)entry);
	*t_ptr = NULL;
}
