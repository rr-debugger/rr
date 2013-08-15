/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "task.h"

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
