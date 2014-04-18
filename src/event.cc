/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "Event"

#include "event.h"

#include <syscall.h>

#include <sstream>
#include <string>

#include "preload/syscall_buffer.h"

#include "log.h"

using namespace std;

Event::Event(EncodedEvent e)
{
	switch ((event_type = EventType(e.type))) {
	case EV_SEGV_RDTSC:
	case EV_EXIT:
	case EV_SCHED:
	case EV_SYSCALLBUF_FLUSH:
	case EV_SYSCALLBUF_ABORT_COMMIT:
	case EV_SYSCALLBUF_RESET:
	case EV_TRACE_TERMINATION:
	case EV_UNSTABLE_EXIT:
	case EV_INTERRUPTED_SYSCALL_NOT_RESTARTED:
	case EV_EXIT_SIGHANDLER:
		new (&Base()) BaseEvent(e.has_exec_info);
		// No auxiliary data.
		assert(0 == e.data);
		return;

	case EV_DESCHED:
		new (&Desched()) DeschedEvent(nullptr);
		Desched().state = DeschedState(e.data);
		return;

	case EV_SIGNAL:
		new (&Signal()) SignalEvent(~DET_SIGNAL_BIT & e.data,
				     DET_SIGNAL_BIT & e.data);
		return;

	case EV_SYSCALL:
		new (&Syscall()) SyscallEvent(e.data);
		Syscall().state = STATE_SYSCALL_ENTRY == e.state ?
				  ENTERING_SYSCALL : EXITING_SYSCALL;
		return;

	default:
		FATAL() <<"Unexpected event "<< *this;
	}
}

Event::Event(const Event& o)
	: event_type(o.event_type)
{
	switch (event_type) {
	case EV_DESCHED:
		new (&Desched()) DeschedEvent(o.Desched());
		return;
	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER:
		new (&Signal()) SignalEvent(o.Signal());
		return;
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		new (&Syscall()) SyscallEvent(o.Syscall());
		return;
	default:
		new (&Base()) BaseEvent(o.Base());
		return;
	}
}

Event::~Event()
{
	switch (event_type) {
	case EV_DESCHED:
		Desched().~DeschedEvent();
		return;
	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER:
		Signal().~SignalEvent();
		return;
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		Syscall().~SyscallEvent();
		return;
	default:
		Base().~BaseEvent();
		return;
	}
}

Event&
Event::operator=(const Event& o)
{
	event_type = o.event_type;
	switch (event_type) {
	case EV_DESCHED:
		Desched().operator=(o.Desched());
		break;
	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER:
		Signal().operator=(o.Signal());
		break;
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		Syscall().operator=(o.Syscall());
		break;
	default:
		Base().operator=(o.Base());
		break;
	}	
	return *this;
}

EncodedEvent
Event::encode() const
{
	EncodedEvent e;
	e.type = event_type;
	e.has_exec_info = has_exec_info();
	// Arbitrarily designate events for which this isn't
	// meaningful as being at "entry".  The events for which this
	// is meaningful set it below.
	e.state = STATE_SYSCALL_ENTRY;

	switch (event_type) {
	case EV_SEGV_RDTSC:
	case EV_EXIT:
	case EV_SCHED:
	case EV_SYSCALLBUF_FLUSH:
	case EV_SYSCALLBUF_ABORT_COMMIT:
	case EV_SYSCALLBUF_RESET:
	case EV_TRACE_TERMINATION:
	case EV_UNSTABLE_EXIT:
	case EV_INTERRUPTED_SYSCALL_NOT_RESTARTED:
	case EV_EXIT_SIGHANDLER:
		// No auxiliary data.
		e.data = 0;
		return e;

	case EV_DESCHED:
		// Disarming the desched notification is a transient
		// state that we shouldn't try to record.
		assert(DISARMING_DESCHED_EVENT != Desched().state);
		e.data = IN_SYSCALL == Desched().state ?
			 ARMING_DESCHED_EVENT : Desched().state;
		return e;

	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER: {
		e.data = Signal().no | (Signal().deterministic ?
					DET_SIGNAL_BIT : 0);
		return e;
	}

	case EV_SYSCALL: {
		// PROCESSING_SYSCALL is a transient state that we
		// should never attempt to record.
		assert(Syscall().state != PROCESSING_SYSCALL);
		e.data = Syscall().is_restart ?
			 SYS_restart_syscall : Syscall().no;
		e.state = (Syscall().state == ENTERING_SYSCALL) ?
			  STATE_SYSCALL_ENTRY : STATE_SYSCALL_EXIT;
		return e;
	}

	default:
		FATAL() <<"Unknown event type "<< event_type;
		return e;	// not reached
	}
}

bool
Event::has_exec_info() const
{
	switch (event_type) {
	case EV_DESCHED: {
		// By the time the tracee is in the buffered syscall,
		// it's by definition already armed the desched event.
		// So we're recording that event ex post facto, and
		// there's no meaningful execution information.
		return IN_SYSCALL != Desched().state;
	}
	default:
		return Base().has_exec_info;
	}
}

bool
Event::is_signal_event() const
{
	switch (event_type) {
	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER:
		return true;
	default:
		return false;
	}
}

bool
Event::is_syscall_event() const
{
	switch (event_type) {
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		return true;
	default:
		return false;
	}
}

void
Event::log() const
{
	LOG(info) << *this;
}

string
Event::str() const
{
	stringstream ss;
	ss << type_name();
	switch (event_type) {
	case EV_DESCHED:
		ss << ": " << syscallname(Desched().rec->syscallno);
		break;
	case EV_SIGNAL:
	case EV_SIGNAL_DELIVERY:
	case EV_SIGNAL_HANDLER:
		ss << ": " << signalname(Signal().no) << "("
		   << (const char*)(Signal().deterministic ? "det" : "async")
		   << ")";
		break;
	case EV_SYSCALL:
	case EV_SYSCALL_INTERRUPTION:
		ss << ": " << syscallname(Syscall().no);
		break;
	default:
		// No auxiliary information.
		break;
	}
	return ss.str();
}

void
Event::transform(EventType new_type)
{
	switch (event_type) {
	case EV_SIGNAL:
		assert(EV_SIGNAL_DELIVERY == new_type);
		break;
	case EV_SIGNAL_DELIVERY:
		assert(EV_SIGNAL_HANDLER == new_type);
		break;
	case EV_SYSCALL:
		assert(EV_SYSCALL_INTERRUPTION == new_type);
		break;
	case EV_SYSCALL_INTERRUPTION:
		assert(EV_SYSCALL == new_type);
		break;
	default:
		FATAL() << "Can't transform immutable "<< *this <<" into "<< new_type;
	}
	event_type = new_type;
}

std::string
Event::type_name() const
{
	switch (event_type) {
	case EV_SENTINEL: return "(none)";
#define CASE(_t) case EV_## _t: return #_t
	CASE(EXIT);
	CASE(EXIT_SIGHANDLER);
	CASE(INTERRUPTED_SYSCALL_NOT_RESTARTED);
	CASE(NOOP);
	CASE(SCHED);
	CASE(SEGV_RDTSC);
	CASE(SYSCALLBUF_FLUSH);
	CASE(SYSCALLBUF_ABORT_COMMIT);
	CASE(SYSCALLBUF_RESET);
	CASE(UNSTABLE_EXIT);
	CASE(DESCHED);
	CASE(SIGNAL);
	CASE(SIGNAL_DELIVERY);
	CASE(SIGNAL_HANDLER);
	CASE(SYSCALL);
	CASE(SYSCALL_INTERRUPTION);
#undef CASE
	default:
		FATAL() <<"Unknown event type "<< event_type;
		return nullptr;	// not reached
	}
}

const char* statename(int state)
{
	switch (state) {
#define CASE(_id) case _id: return #_id
	CASE(STATE_SYSCALL_ENTRY);
	CASE(STATE_SYSCALL_EXIT);
#undef CASE

	default:
		return "???state";
	}
}
