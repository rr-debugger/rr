/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Event.h"

#include <syscall.h>

#include <sstream>
#include <string>

#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

Event::Event(const Event& o) : event_type(o.event_type) {
  switch (event_type) {
    case EV_DESCHED:
      new (&Desched()) DeschedEvent(o.Desched());
      return;
    case EV_PATCH_SYSCALL:
      new (&PatchSyscall()) PatchSyscallEvent(o.PatchSyscall());
      return;
    case EV_SCHED:
      new (&Sched()) SchedEvent(o.Sched());
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
      return;
  }
}

Event::~Event() {
  switch (event_type) {
    case EV_DESCHED:
      Desched().~DeschedEvent();
      return;
    case EV_PATCH_SYSCALL:
      PatchSyscall().~PatchSyscallEvent();
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

bool Event::record_regs() const {
  switch (type()) {
    case EV_INSTRUCTION_TRAP:
    case EV_PATCH_SYSCALL:
    case EV_SCHED:
    case EV_SYSCALL:
    case EV_SIGNAL:
    case EV_SIGNAL_DELIVERY:
    case EV_SIGNAL_HANDLER:
      return true;
    default:
      return false;
  }
}

bool Event::record_extra_regs() const {
  switch (type()) {
    case EV_SYSCALL: {
      const SyscallEvent& sys_ev = Syscall();
      // sigreturn/rt_sigreturn restores register state
      // execve sets everything under the sun, and
      // pkey_alloc modifies the PKRU register.
      return sys_ev.state == EXITING_SYSCALL &&
             (is_sigreturn(sys_ev.number, sys_ev.arch()) ||
              sys_ev.is_exec() ||
              is_pkey_alloc_syscall(sys_ev.number, sys_ev.arch()));
    }
    case EV_SIGNAL:
      // Record extra regs so we can deliver the signal at the
      // right time even when GP regs and ticks values are unchanged
      // but extra regs have changed.
      return true;
    case EV_SIGNAL_HANDLER:
      // entering a signal handler seems to clear FP/SSE regs,
      // so record these effects.
      return true;
    default:
      return false;
  }
}

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
      return ""; // not reached
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

bool Event::can_checkpoint_at() const {
  if (has_ticks_slop()) {
    return false;
  }
  switch (type()) {
    case EV_EXIT:
    // At exits, we can't clone the exiting tasks, so
    // don't event bother trying to checkpoint.
    case EV_SYSCALLBUF_RESET:
    // RESETs are usually inserted in between syscall
    // entry/exit.  Do not attempting to checkpoint at
    // RESETs.  Users would never want to do that anyway.
    case EV_TRACE_TERMINATION:
      // There's nothing to checkpoint at the end of a trace.
      return false;
    default:
      return true;
  }
}

} // namespace rr
