/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "task.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"

/**
 * Stores the table of signal dispositions and metadata for an
 * arbitrary set of tasks.  Each of those task must own one one of the
 * |refcount|s while they still refer to this.
 */
struct sighandlers {
	int refcount;
	struct {
		sig_handler_t handler;
		int resethand;
	} handlers[_NSIG];
};

/**
 * Push a new event onto |t|'s event stack of type |type|.
 */
static void push_new_event(struct task* t, int type)
{
	struct event ev = { .type = type };
	FIXEDSTACK_PUSH(&t->pending_events, ev);
	t->ev = FIXEDSTACK_TOP(&t->pending_events);
}

/**
 * Pop the pending-event stack and return the type of the previous top
 * element.
 */
static int pop_event(struct task* t)
{
	int last_top_type = FIXEDSTACK_POP(&t->pending_events).type;
	t->ev = !FIXEDSTACK_EMPTY(&t->pending_events) ?
		  FIXEDSTACK_TOP(&t->pending_events) : NULL;
	return last_top_type;
}

void push_pseudosig(struct task* t, int no, int has_exec_info)
{
	push_new_event(t, EV_PSEUDOSIG);
	t->ev->pseudosig.no = no;
	t->ev->pseudosig.has_exec_info = has_exec_info;
}

void pop_pseudosig(struct task* t)
{
	int type = pop_event(t);
	assert(EV_PSEUDOSIG == type);
}

void push_signal(struct task* t, int no, int deterministic)
{
	push_new_event(t, EV_SIGNAL);
	t->ev->signal.no = no;
	t->ev->signal.deterministic = deterministic;
}

void pop_signal(struct task* t)
{
	int type = pop_event(t);
	assert(EV_SIGNAL == type);
}

void push_syscall(struct task* t, int no)
{
	push_new_event(t, EV_SYSCALL);
	t->ev->syscall.no = no;
}

void pop_syscall(struct task* t)
{
	int type = pop_event(t);
	assert(EV_SYSCALL == type);
}

static void assert_valid(const struct sighandlers* t)
{
	assert(t->refcount > 0);
}

static void assert_table_has_sig(const struct sighandlers* t, int sig)
{
	assert_valid(t);
	assert(0 < sig && sig < ALEN(t->handlers));
}

static int is_user_handler(sig_handler_t sh)
{
	/* We assume this in order to make the check below simpler.
	 * TODO: static assert */
	assert((void*)1 == SIG_IGN);

	return !!((uintptr_t)sh & ~(uintptr_t)SIG_IGN);
}

struct sighandlers* sighandlers_new()
{
	struct sighandlers* t = calloc(1, sizeof(*t));

	/* We assume this in order to skip explicitly initializing the
	 * table.  TODO: static assert */
	assert(NULL == SIG_DFL);

	t->refcount = 1;
	return t;
}

void sighandlers_init_from_current_process(struct sighandlers* table)
{
	int i;
	for (i = 0; i < ALEN(table->handlers); ++i) {
		struct sigaction act;

		if (-1 == sigaction(i, NULL, &act)) {
			/* EINVAL means we're querying an unused
			 * signal number. */
			assert(EINVAL == errno);
			assert(SIG_DFL == table->handlers[i].handler);
			assert(!table->handlers[i].resethand);
			continue;
		}
		table->handlers[i].handler = (SA_SIGINFO & act.sa_flags) ?
					     (void*)act.sa_sigaction :
					     act.sa_handler;
		table->handlers[i].resethand = (act.sa_flags & SA_RESETHAND);
	}
}

int sighandlers_has_user_handler(const struct sighandlers* table, int sig)
{
	assert_table_has_sig(table, sig);
	return is_user_handler(table->handlers[sig].handler);
}

int sighandlers_is_resethand(const struct sighandlers* table, int sig)
{
	assert_table_has_sig(table, sig);
	return !!table->handlers[sig].resethand;
}

void sighandlers_set_disposition(struct sighandlers* table, int sig,
				 sig_handler_t disp, int resethand)
{
	assert_table_has_sig(table, sig);
	table->handlers[sig].handler = disp;
	/* The sigaction() spec says to only honor SA_RESETHAND if
	 * it's set for a user signal handler.  So ignore it if it's
	 * specified for SIG_IGN.  (It would have no effect for
	 * SIG_DFL.) */
	table->handlers[sig].resethand = is_user_handler(disp) ? resethand : 0;
}

struct sighandlers* sighandlers_copy(struct sighandlers* from)
{
	struct sighandlers* copy = sighandlers_new();

	memcpy(copy, from, sizeof(*copy));
	copy->refcount = 1;

	return copy;
}

struct sighandlers* sighandlers_ref(struct sighandlers* table)
{
	assert_valid(table);
	++table->refcount;
	return table;
}

void sighandlers_reset_user_handlers(struct sighandlers* table)
{
	int i;

	for (i = 0; i < ALEN(table->handlers); ++i) {
		sig_handler_t oh = table->handlers[i].handler;
		/* If the handler was a user handler, reset to
		 * default.  If it was SIG_IGN or SIG_DFL, leave it
		 * alone. */
		if (is_user_handler(oh)) {
			table->handlers[i].handler = SIG_DFL;
			table->handlers[i].resethand = 0;
		}
	}
}

void sighandlers_unref(struct sighandlers** table)
{
	struct sighandlers* t;

	if (!table || !*table) {
		return;
	}

	t = *table;
	*table = NULL;
	assert_valid(t);

	if (0 == --t->refcount) {
		free(t);
	}
}
