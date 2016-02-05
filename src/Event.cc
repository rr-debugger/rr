/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Event"

#include "Event.h"

#include <syscall.h>

#include <sstream>
#include <string>

#include "preload/preload_interface.h"

#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"

using namespace rr;
using namespace std;

Event::Event(EncodedEvent e) {
  switch (event_type = e.type) {
    case EV_SEGV_RDTSC:
    case EV_EXIT:
    case EV_SCHED:
    case EV_SYSCALLBUF_FLUSH:
    case EV_SYSCALLBUF_ABORT_COMMIT:
    case EV_SYSCALLBUF_RESET:
    case EV_PATCH_SYSCALL:
    case EV_GROW_MAP:
    case EV_TRACE_TERMINATION:
    case EV_UNSTABLE_EXIT:
    case EV_INTERRUPTED_SYSCALL_NOT_RESTARTED:
    case EV_EXIT_SIGHANDLER:
      new (&Base()) BaseEvent(e.has_exec_info, e.arch());
      // No auxiliary data.
      assert(0 == e.data);
      return;

    case EV_DESCHED:
      new (&Desched()) DeschedEvent(nullptr, e.arch());
      return;

    case EV_SIGNAL:
    case EV_SIGNAL_DELIVERY:
    case EV_SIGNAL_HANDLER:
      new (&Signal()) SignalEvent(
          ~DET_SIGNAL_BIT & e.data,
          (DET_SIGNAL_BIT & e.data) ? DETERMINISTIC_SIG : NONDETERMINISTIC_SIG,
          e.arch());
      return;

    case EV_SYSCALL:
      new (&Syscall()) SyscallEvent(e.data, e.arch());
      Syscall().state = e.is_syscall_entry ? ENTERING_SYSCALL : EXITING_SYSCALL;
      return;

    default:
      FATAL() << "Unexpected event " << *this;
  }
}

Event::Event(const Event& o) : event_type(o.event_type) {
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

Event::~Event() {
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

Event& Event::operator=(const Event& o) {
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

static void set_encoded_event_data(EncodedEvent* e, int data) {
  e->data = data;
  // Ensure that e->data is wide enough for the data
  assert(e->data == data);
}

EncodedEvent Event::encode() const {
  EncodedEvent e;
  e.type = event_type;
  e.has_exec_info = has_exec_info();
  e.arch_ = arch();
  // Arbitrarily designate events for which this isn't
  // meaningful as being at "entry".  The events for which this
  // is meaningful set it below.
  e.is_syscall_entry = true;

  switch (event_type) {
    case EV_SEGV_RDTSC:
    case EV_EXIT:
    case EV_SCHED:
    case EV_SYSCALLBUF_FLUSH:
    case EV_SYSCALLBUF_ABORT_COMMIT:
    case EV_SYSCALLBUF_RESET:
    case EV_PATCH_SYSCALL:
    case EV_GROW_MAP:
    case EV_TRACE_TERMINATION:
    case EV_UNSTABLE_EXIT:
    case EV_INTERRUPTED_SYSCALL_NOT_RESTARTED:
    case EV_EXIT_SIGHANDLER:
      // No auxiliary data.
      set_encoded_event_data(&e, 0);
      return e;

    case EV_SIGNAL:
    case EV_SIGNAL_DELIVERY:
    case EV_SIGNAL_HANDLER: {
      set_encoded_event_data(
          &e, Signal().siginfo.si_signo |
                  (Signal().deterministic == DETERMINISTIC_SIG ? DET_SIGNAL_BIT
                                                               : 0));
      return e;
    }

    case EV_SYSCALL: {
      // PROCESSING_SYSCALL is a transient state that we
      // should never attempt to record.
      assert(Syscall().state != PROCESSING_SYSCALL);
      set_encoded_event_data(
          &e, Syscall().is_restart ? syscall_number_for_restart_syscall(e.arch_)
                                   : Syscall().number);
      e.is_syscall_entry = Syscall().state == ENTERING_SYSCALL;
      return e;
    }

    default:
      FATAL() << "Unknown event type " << event_type;
      return e; // not reached
  }
}

HasExecInfo Event::record_exec_info() const { return Base().has_exec_info; }

bool Event::has_ticks_slop() const {
  switch (type()) {
    case EV_SYSCALLBUF_ABORT_COMMIT:
    case EV_SYSCALLBUF_FLUSH:
    case EV_SYSCALLBUF_RESET:
    case EV_INTERRUPTED_SYSCALL_NOT_RESTARTED:
    case EV_DESCHED:
    case EV_GROW_MAP:
      return true;
    default:
      return false;
  }
}

bool Event::is_signal_event() const {
  switch (event_type) {
    case EV_SIGNAL:
    case EV_SIGNAL_DELIVERY:
    case EV_SIGNAL_HANDLER:
      return true;
    default:
      return false;
  }
}

bool Event::is_syscall_event() const {
  switch (event_type) {
    case EV_SYSCALL:
    case EV_SYSCALL_INTERRUPTION:
      return true;
    default:
      return false;
  }
}

void Event::log() const { LOG(info) << *this; }

string Event::str() const {
  stringstream ss;
  ss << type_name();
  switch (event_type) {
    case EV_SIGNAL:
    case EV_SIGNAL_DELIVERY:
    case EV_SIGNAL_HANDLER:
      ss << ": " << signal_name(Signal().siginfo.si_signo) << "("
         << (const char*)(Signal().deterministic == DETERMINISTIC_SIG ? "det"
                                                                      : "async")
         << ")";
      break;
    case EV_SYSCALL:
    case EV_SYSCALL_INTERRUPTION:
      ss << ": " << syscall_name(Syscall().number, Syscall().regs.arch());
      break;
    default:
      // No auxiliary information.
      break;
  }
  return ss.str();
}

void Event::transform(EventType new_type) {
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
      FATAL() << "Can't transform immutable " << *this << " into " << new_type;
  }
  event_type = new_type;
}

std::string Event::type_name() const {
  switch (event_type) {
    case EV_SENTINEL:
      return "(none)";
#define CASE(_t)                                                               \
  case EV_##_t:                                                                \
    return #_t
      CASE(EXIT);
      CASE(EXIT_SIGHANDLER);
      CASE(INTERRUPTED_SYSCALL_NOT_RESTARTED);
      CASE(NOOP);
      CASE(SCHED);
      CASE(SEGV_RDTSC);
      CASE(SYSCALLBUF_FLUSH);
      CASE(SYSCALLBUF_ABORT_COMMIT);
      CASE(SYSCALLBUF_RESET);
      CASE(PATCH_SYSCALL);
      CASE(GROW_MAP);
      CASE(UNSTABLE_EXIT);
      CASE(DESCHED);
      CASE(SIGNAL);
      CASE(SIGNAL_DELIVERY);
      CASE(SIGNAL_HANDLER);
      CASE(SYSCALL);
      CASE(SYSCALL_INTERRUPTION);
      CASE(TRACE_TERMINATION);
#undef CASE
    default:
      FATAL() << "Unknown event type " << event_type;
      return nullptr; // not reached
  }
}

SignalEvent::SignalEvent(const siginfo_t& siginfo, SupportedArch arch)
    : BaseEvent(HAS_EXEC_INFO, arch),
      siginfo(siginfo),
      deterministic(is_deterministic_signal(siginfo)) {}

const char* state_name(SyscallState state) {
  switch (state) {
#define CASE(_id)                                                              \
  case _id:                                                                    \
    return #_id
    CASE(NO_SYSCALL);
    CASE(ENTERING_SYSCALL);
    CASE(PROCESSING_SYSCALL);
    CASE(EXITING_SYSCALL);
#undef CASE
    default:
      return "???state";
  }
}
