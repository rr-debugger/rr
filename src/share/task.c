/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "task.h"

#include <stdlib.h>
#include <string.h>

#include "dbg.h"
#include "syscall_buffer.h"
#include "util.h"

/**
 * "Mix-in" for heap structs to enable them to be refcounted using the
 * |refcounted_()| helpers below.  Your struct must have a |struct
 * refcounted| field inline, first, as follows.  The field name
 * doesn't matter.
 *
 *   struct foo {
 *     struct refcounted _;
 *     ...
 *   };
 */
struct refcounted {
	int refcount;
};

/**
 * Tracks a group of tasks with an associated ID, set from the
 * original "thread group leader", the child of |fork()| which became
 * the ancestor of all other threads in the group.  Each constituent
 * task must own a reference to this.
 */
struct task_group {
	struct refcounted _;
	pid_t tgid;
	TAILQ_HEAD(task_group_list, task) tasks;
};

/**
 * Stores the table of signal dispositions and metadata for an
 * arbitrary set of tasks.  Each of those tasks must own one one of
 * the |refcount|s while they still refer to this.
 */
struct sighandlers {
	struct refcounted _;
	struct {
		sig_handler_t handler;
		int resethand;
	} handlers[_NSIG];
};

/**
 * Initializes the first reference to the struct.
 * |refcounted_unref()| must be called to release that reference.
 */
static void refcounted_init(void* p)
{
	struct refcounted* r = p;
	r->refcount = 1;
}

static void refcounted_assert_valid(const void* p)
{
	const struct refcounted* r = p;
	assert(r->refcount > 0);
}

/**
 * Add a reference to |p|, so that |refcounted_unref()| must be called
 * one more time to free |p|.
 */
static void* refcounted_ref(void* p)
{
	struct refcounted* r = p;
	refcounted_assert_valid(r);
	++r->refcount;
	return r;
}

/**
 * Remove a reference to |*pp| and return |*pp| if the released
 * reference was the last and |*pp| needs to be freed; NULL otherwise.
 * It's OK to pass a NULL pointer or pointer to NULL.
 */
static void* refcounted_unref(void** pp)
{
	struct refcounted* r;
	if (!pp || !(r = *pp)) {
		return NULL;
	}
	*pp = NULL;
	refcounted_assert_valid(r);
	return (0 == --r->refcount) ? r : NULL;
}

static const char* event_type_name(int type)
{
	switch (type) {
	case EV_NONE: return "(none)";
#define CASE(_t) case EV_## _t: return #_t
		CASE(DESCHED);
		CASE(PSEUDOSIG);
		CASE(SIGNAL);
		CASE(SIGNAL_DELIVERY);
		CASE(SIGNAL_HANDLER);
		CASE(SYSCALL);
		CASE(SYSCALL_INTERRUPTION);
#undef CASE
	default:
		fatal("Unknown event type %d", type);
	}
}

static int is_syscall_event(int type) {
	switch (type) {
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		return 1;
	default:
		return 0;
	}
}

int task_may_be_blocked(struct task* t)
{
	return (t->ev
		&& ((EV_SYSCALL == t->ev->type
		     && PROCESSING_SYSCALL == t->ev->syscall.state)
		    || (EV_SIGNAL_DELIVERY == t->ev->type
			&& t->ev->signal.delivered)));
}

const struct syscallbuf_record* task_desched_rec(const struct task* t)
{
	return (is_syscall_event(t->ev->type) ? t->ev->syscall.desched_rec :
		(EV_DESCHED == t->ev->type) ? t->ev->desched.rec : NULL);
}

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
static void pop_event(struct task* t, int expected_type)
{
	int last_top_type = FIXEDSTACK_POP(&t->pending_events).type;

	t->ev = FIXEDSTACK_TOP(&t->pending_events);
	assert_exec(t, expected_type == last_top_type,
		    "Should have popped event %s but popped %s instead",
		    event_type_name(expected_type),
		    event_type_name(last_top_type));
}

void push_placeholder_event(struct task* t)
{
	assert(FIXEDSTACK_EMPTY(&t->pending_events));
	push_new_event(t, EV_NONE);
}

void push_desched(struct task* t, const struct syscallbuf_record* rec)
{
	assert_exec(t, !task_desched_rec(t), "Must have zero or one desched");

	push_new_event(t, EV_DESCHED);
	t->ev->desched.state = IN_SYSCALL;
	t->ev->desched.rec = rec;
}

void pop_desched(struct task* t)
{
	assert_exec(t, task_desched_rec(t), "Must have desched_rec to pop");

	pop_event(t, EV_DESCHED);
}

void push_pseudosig(struct task* t, int no, int has_exec_info)
{
	push_new_event(t, EV_PSEUDOSIG);
	t->ev->pseudosig.no = no;
	t->ev->pseudosig.has_exec_info = has_exec_info;
}

void pop_pseudosig(struct task* t)
{
	pop_event(t, EV_PSEUDOSIG);
}

void push_pending_signal(struct task* t, int no, int deterministic)
{
	push_new_event(t, EV_SIGNAL);
	t->ev->signal.no = no;
	t->ev->signal.deterministic = deterministic;
}

void pop_signal_delivery(struct task* t)
{
	pop_event(t, EV_SIGNAL_DELIVERY);
}

void pop_signal_handler(struct task* t)
{
	pop_event(t, EV_SIGNAL_HANDLER);
}

void push_syscall(struct task* t, int no)
{
	push_new_event(t, EV_SYSCALL);
	t->ev->syscall.no = no;
}

void pop_syscall(struct task* t)
{
	pop_event(t, EV_SYSCALL);
}

void push_syscall_interruption(struct task* t, int no,
			       const struct user_regs_struct* args)
{
	const struct syscallbuf_record* rec = task_desched_rec(t);

	assert_exec(t, rec || REPLAY == rr_flags()->option,
		    "Must be interrupting desched during recording");

	push_new_event(t, EV_SYSCALL_INTERRUPTION);
	t->ev->syscall.state = EXITING_SYSCALL;
	t->ev->syscall.no = no;
	t->ev->syscall.desched_rec = rec;
	memcpy(&t->ev->syscall.regs, args, sizeof(t->ev->syscall.regs));
}

void pop_syscall_interruption(struct task* t)
{
	pop_event(t, EV_SYSCALL_INTERRUPTION);
}

void log_pending_events(const struct task* t)
{
	ssize_t depth = FIXEDSTACK_DEPTH(&t->pending_events);
	int i;

	assert(depth > 0);
	if (1 == depth) {
		log_info("(no pending events)");
		return;
	}

	/* The event at depth 0 is the placeholder event, which isn't
	 * useful to log.  Skip it. */
	for (i = depth - 1; i >= 1; --i) {
		log_event(&t->pending_events.elts[i]);
	}
}

void log_event(const struct event* ev)
{
	const char* name = event_name(ev);
	switch (ev->type) {
	case EV_NONE:
		log_info("%s", name);
		return;
	case EV_DESCHED:
		log_info("%s: %s", name,
			 syscallname(ev->desched.rec->syscallno));
		break;
	case EV_PSEUDOSIG:
		log_info("%s: %d", name, ev->pseudosig.no);
		return;
	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER:
		log_info("%s: %s", name, signalname(ev->signal.no));
		return;
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		log_info("%s: %s", name, syscallname(ev->syscall.no));
		return;
	default:
		fatal("Unknown event type %d", ev->type);
	}
}

const char* event_name(const struct event* ev)
{
	return event_type_name(ev->type);
}

struct task_group* task_group_new_and_add(struct task* t)
{
	struct task_group* tg = calloc(1, sizeof(*tg));

	refcounted_init(tg);

	tg->tgid = t->tid;
	TAILQ_INIT(&tg->tasks);
	TAILQ_INSERT_TAIL(&tg->tasks, t, tgentry);

	return tg;
}

struct task_group* task_group_add_and_ref(struct task_group* tg,
					  struct task* t)
{
	refcounted_assert_valid(tg);
	TAILQ_INSERT_TAIL(&tg->tasks, t, tgentry);
	return refcounted_ref(tg);
}

void task_group_destabilize(struct task_group* tg)
{
	struct task* t;
	TAILQ_FOREACH(t, &tg->tasks, tgentry) {
		t->unstable = 1;
	}
}

pid_t task_group_get_tgid(const struct task_group* tg)
{
	refcounted_assert_valid(tg);
	return tg->tgid;
}

void task_group_remove_and_unref(struct task* t)
{
	struct task_group* to_free;

	TAILQ_REMOVE(&t->task_group->tasks, t, tgentry);

	to_free = refcounted_unref((void**)&t->task_group);
	if (to_free) {
		assert(TAILQ_EMPTY(&to_free->tasks));
		free(to_free);
	}
}

static void assert_table_has_sig(const struct sighandlers* t, int sig)
{
	refcounted_assert_valid(t);
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
	refcounted_init(t);
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
	refcounted_init(copy);

	return copy;
}

struct sighandlers* sighandlers_ref(struct sighandlers* table)
{
	return refcounted_ref(table);
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
	struct sighandlers* to_free = refcounted_unref((void**)table);
	if (to_free) {
		free(to_free);
	}
}
