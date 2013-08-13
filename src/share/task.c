/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "task.h"

/**
 * Push a new event onto |ctx|'s event stack of type |type|.
 */
static void push_new_event(struct context* ctx, int type)
{
	struct event ev = { .type = type };
	FIXEDSTACK_PUSH(&ctx->pending_events, ev);
	ctx->ev = FIXEDSTACK_TOP(&ctx->pending_events);
}

/**
 * Pop the pending-event stack and return the type of the previous top
 * element.
 */
static int pop_event(struct context* ctx)
{
	int last_top_type = FIXEDSTACK_POP(&ctx->pending_events).type;
	ctx->ev = !FIXEDSTACK_EMPTY(&ctx->pending_events) ?
		  FIXEDSTACK_TOP(&ctx->pending_events) : NULL;
	return last_top_type;
}

void push_pseudosig(struct context* ctx, int no, int has_exec_info)
{
	push_new_event(ctx, EV_PSEUDOSIG);
	ctx->ev->pseudosig.no = no;
	ctx->ev->pseudosig.has_exec_info = has_exec_info;
}

void pop_pseudosig(struct context* ctx)
{
	int type = pop_event(ctx);
	assert(EV_PSEUDOSIG == type);
}

void push_signal(struct context* ctx, int no, int deterministic)
{
	push_new_event(ctx, EV_SIGNAL);
	ctx->ev->signal.no = no;
	ctx->ev->signal.deterministic = deterministic;
}

void pop_signal(struct context* ctx)
{
	int type = pop_event(ctx);
	assert(EV_SIGNAL == type);
}

void push_syscall(struct context* ctx, int no)
{
	push_new_event(ctx, EV_SYSCALL);
	ctx->ev->syscall.no = no;
}

void pop_syscall(struct context* ctx)
{
	int type = pop_event(ctx);
	assert(EV_SYSCALL == type);
}
