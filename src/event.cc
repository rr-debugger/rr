/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Event"

#include "event.h"

#include "task.h"

static const char* event_type_name(int type)
{
	switch (type) {
	case EV_SENTINEL: return "(none)";
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

int is_syscall_event(int type)
{
	switch (type) {
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		return 1;
	default:
		return 0;
	}
}

/**
 * Push a new event onto |t|'s event stack of type |type|.
 */
static void push_new_event(Task* t, EventType type)
{
	struct event ev;
	memset(&ev, 0, sizeof(ev));
	ev.type = EventType(type);

	FIXEDSTACK_PUSH(&t->pending_events, ev);
}

/**
 * Pop the pending-event stack and return the type of the previous top
 * element.
 */
static void pop_event(Task* t, int expected_type)
{
	int last_top_type;

	assert_exec(t, FIXEDSTACK_DEPTH(&t->pending_events) > 1,
		    "Attempting to pop sentinel event");

	last_top_type = FIXEDSTACK_POP(&t->pending_events).type;
	assert_exec(t, expected_type == last_top_type,
		    "Should have popped event %s but popped %s instead",
		    event_type_name(expected_type),
		    event_type_name(last_top_type));
}

void push_placeholder_event(Task* t)
{
	assert(FIXEDSTACK_EMPTY(&t->pending_events));
	push_new_event(t, EV_SENTINEL);
}

void push_noop(Task* t)
{
	push_new_event(t, EV_NOOP);
}

void pop_noop(Task* t)
{
	pop_event(t, EV_NOOP);
}

void push_desched(Task* t, const struct syscallbuf_record* rec)
{
	assert_exec(t, !t->desched_rec(), "Must have zero or one desched");

	push_new_event(t, EV_DESCHED);
	t->ev().desched.state = IN_SYSCALL;
	t->ev().desched.rec = rec;
}

void pop_desched(Task* t)
{
	assert_exec(t, t->desched_rec(), "Must have desched_rec to pop");

	pop_event(t, EV_DESCHED);
}

void push_pseudosig(Task* t, PseudosigType no, int has_exec_info)
{
	push_new_event(t, EV_PSEUDOSIG);
	t->ev().pseudosig.no = no;
	t->ev().pseudosig.has_exec_info = has_exec_info;
}

void pop_pseudosig(Task* t)
{
	pop_event(t, EV_PSEUDOSIG);
}

void push_pending_signal(Task* t, int no, int deterministic)
{
	push_new_event(t, EV_SIGNAL);
	t->ev().signal.no = no;
	t->ev().signal.deterministic = deterministic;
}

void pop_signal_delivery(Task* t)
{
	pop_event(t, EV_SIGNAL_DELIVERY);
}

void pop_signal_handler(Task* t)
{
	pop_event(t, EV_SIGNAL_HANDLER);
}

void push_syscall(Task* t, int no)
{
	push_new_event(t, EV_SYSCALL);
	t->ev().syscall.no = no;
}

void pop_syscall(Task* t)
{
	pop_event(t, EV_SYSCALL);
}

void push_syscall_interruption(Task* t, int no)
{
	const struct syscallbuf_record* rec = t->desched_rec();

	assert_exec(t, rec || REPLAY == rr_flags()->option,
		    "Must be interrupting desched during recording");

	push_new_event(t, EV_SYSCALL_INTERRUPTION);
	t->ev().syscall.state = EXITING_SYSCALL;
	t->ev().syscall.no = no;
	t->ev().syscall.desched_rec = rec;
	t->ev().syscall.regs = t->regs();
}

void pop_syscall_interruption(Task* t)
{
	pop_event(t, EV_SYSCALL_INTERRUPTION);
}

void log_pending_events(const Task* t)
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
	const char* name = event_name(*ev);
	switch (ev->type) {
	case EV_SENTINEL:
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


const char* statename(int state)
{
	switch (state) {
#define CASE(_id) case _id: return #_id
	CASE(STATE_SYSCALL_ENTRY);
	CASE(STATE_SYSCALL_EXIT);
	CASE(STATE_PRE_MMAP_ACCESS);
#undef CASE

	default:
		return "???state";
	}
}

static const char* decode_signal_event(int sig)
{
	int det;
	static __thread char buf[] =
		"SIGREALLYREALLYLONGNAME(asynchronouslydelivered)";

	if (FIRST_RR_PSEUDOSIGNAL <= sig && sig <= LAST_RR_PSEUDOSIGNAL) {
		switch (sig) {
#define CASE(_id) case _id: return #_id
		CASE(SIG_SEGV_RDTSC);
		CASE(USR_EXIT);
		CASE(USR_SCHED);
		CASE(USR_SYSCALLBUF_FLUSH);
		CASE(USR_SYSCALLBUF_ABORT_COMMIT);
		CASE(USR_SYSCALLBUF_RESET);
		CASE(USR_ARM_DESCHED);
		CASE(USR_DISARM_DESCHED);
		CASE(USR_NOOP);
#undef CASE
		}
	}

	if (sig < FIRST_DET_SIGNAL) {
		return "???pseudosignal";
	}

	sig = -sig;
	det = sig & DET_SIGNAL_BIT;
	sig &= ~DET_SIGNAL_BIT;

	snprintf(buf, sizeof(buf) - 1, "%s(%s)",
		 signalname(sig), det ? "det" : "async");
	return buf;
}

const char* strevent(int event)
{
	if (0 > event) {
		return decode_signal_event(event);
	}
	if (0 <= event) {
		return syscallname(event);
	}
	return "???event";
}

const char* event_name(const struct event& ev)
{
	return event_type_name(ev.type);
}
