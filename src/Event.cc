/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Event.h"

#include <syscall.h>

#include <sstream>
#include <string>

#include "preload/preload_interface.h"

#include "RecordTask.h"
#include "Task.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

Event::Event(EventType type, HasExecInfo has_exec_info, SupportedArch arch)
    : event_type(type), base(has_exec_info, arch) {
  switch (event_type) {
    case EV_NOOP:
    case EV_SECCOMP_TRAP:
    case EV_SENTINEL:
    case EV_INSTRUCTION_TRAP:
    case EV_EXIT:
    case EV_SCHED:
    case EV_SYSCALLBUF_ABORT_COMMIT:
    case EV_SYSCALLBUF_RESET:
    case EV_SYSCALL_INTERRUPTION:
    case EV_PATCH_SYSCALL:
    case EV_GROW_MAP:
    case EV_TRACE_TERMINATION:
      new (&Base()) BaseEvent(has_exec_info, arch);
      return;

    case EV_DESCHED:
      new (&Desched()) DeschedEvent(nullptr, arch);
      return;

    case EV_SYSCALLBUF_FLUSH:
      new (&SyscallbufFlush()) SyscallbufFlushEvent(arch);
      return;

    case EV_SIGNAL:
    case EV_SIGNAL_DELIVERY:
    case EV_SIGNAL_HANDLER:
      new (&Signal()) SignalEvent(arch);
      return;

    case EV_SYSCALL:
      new (&Syscall()) SyscallEvent(0, arch);
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
    case EV_SYSCALLBUF_FLUSH:
      new (&SyscallbufFlush()) SyscallbufFlushEvent(o.SyscallbufFlush());
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
    case EV_SYSCALLBUF_FLUSH:
      SyscallbufFlush().~SyscallbufFlushEvent();
      return;
    default:
      Base().~BaseEvent();
      return;
  }
}

Event& Event::operator=(const Event& o) {
  if (this == &o) {
    return *this;
  }
  this->~Event();
  new (this) Event(o);
  return *this;
}

HasExecInfo Event::record_exec_info() const { return Base().has_exec_info; }

bool Event::has_ticks_slop() const {
  switch (type()) {
    case EV_SYSCALLBUF_ABORT_COMMIT:
    case EV_SYSCALLBUF_FLUSH:
    case EV_SYSCALLBUF_RESET:
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
      DEBUG_ASSERT(EV_SIGNAL_DELIVERY == new_type);
      break;
    case EV_SIGNAL_DELIVERY:
      DEBUG_ASSERT(EV_SIGNAL_HANDLER == new_type);
      break;
    case EV_SYSCALL:
      DEBUG_ASSERT(EV_SYSCALL_INTERRUPTION == new_type);
      break;
    case EV_SYSCALL_INTERRUPTION:
      DEBUG_ASSERT(EV_SYSCALL == new_type);
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
      CASE(NOOP);
      CASE(SCHED);
      CASE(SECCOMP_TRAP);
      CASE(INSTRUCTION_TRAP);
      CASE(SYSCALLBUF_FLUSH);
      CASE(SYSCALLBUF_ABORT_COMMIT);
      CASE(SYSCALLBUF_RESET);
      CASE(PATCH_SYSCALL);
      CASE(GROW_MAP);
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

SignalEvent::SignalEvent(const siginfo_t& siginfo,
                         SignalDeterministic deterministic, RecordTask* t)
    : BaseEvent(HAS_EXEC_INFO, t->arch()),
      siginfo(siginfo),
      deterministic(deterministic) {
  int sig = siginfo.si_signo;
  if (t->is_fatal_signal(sig, deterministic)) {
    disposition = DISPOSITION_FATAL;
  } else if (t->signal_has_user_handler(sig) && !t->is_sig_blocked(sig)) {
    disposition = DISPOSITION_USER_HANDLER;
  } else {
    disposition = DISPOSITION_IGNORED;
  }
}

const char* state_name(SyscallState state) {
  switch (state) {
#define CASE(_id)                                                              \
  case _id:                                                                    \
    return #_id
    CASE(NO_SYSCALL);
    CASE(ENTERING_SYSCALL_PTRACE);
    CASE(ENTERING_SYSCALL);
    CASE(PROCESSING_SYSCALL);
    CASE(EXITING_SYSCALL);
#undef CASE
    default:
      return "???state";
  }
}

} // namespace rr
