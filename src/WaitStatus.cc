/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "WaitStatus.h"

#include <sys/types.h>
#include <sys/wait.h>

#include "RecordTask.h"
#include "core.h"
#include "kernel_metadata.h"
#include "kernel_supplement.h"
#include "log.h"

using namespace std;

namespace rr {

WaitStatus::Type WaitStatus::type() const {
  if (exit_code() >= 0) {
    return EXIT;
  }
  if (fatal_sig() > 0) {
    return FATAL_SIGNAL;
  }
  if (stop_sig() > 0) {
    return SIGNAL_STOP;
  }
  if (group_stop() > 0) {
    return GROUP_STOP;
  }
  if (is_syscall()) {
    return SYSCALL_STOP;
  }
  if (ptrace_event() > 0) {
    return PTRACE_EVENT;
  }
  FATAL() << "Status " << HEX(status) << " not understood";
  return EXIT;
}

int WaitStatus::exit_code() const {
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int WaitStatus::fatal_sig() const {
  return WIFSIGNALED(status) ? WTERMSIG(status) : 0;
}

int WaitStatus::stop_sig() const {
  if (!WIFSTOPPED(status) || ((status >> 16) & 0xff)) {
    return 0;
  }
  int sig = WSTOPSIG(status);
  if (sig == (SIGTRAP | 0x80)) {
    return 0;
  }
  sig &= ~0x80;
  return sig ? sig : SIGSTOP;
}

int WaitStatus::group_stop() const {
  if (!WIFSTOPPED(status) || ((status >> 16) & 0xff) != PTRACE_EVENT_STOP) {
    return 0;
  }
  int sig = WSTOPSIG(status);
  sig &= ~0x80;
  return sig ? sig : SIGSTOP;
}

bool WaitStatus::is_syscall() const {
  if (!WIFSTOPPED(status) || ptrace_event()) {
    return 0;
  }
  return WSTOPSIG(status) == (SIGTRAP | 0x80);
}

int WaitStatus::ptrace_event() const {
  int event = (status >> 16) & 0xff;
  return event == PTRACE_EVENT_STOP ? 0 : event;
}

int WaitStatus::ptrace_signal() const {
  return WIFSTOPPED(status) ? (WSTOPSIG(status) & 0x7f) : 0;
}

WaitStatus WaitStatus::for_exit_code(int code) {
  DEBUG_ASSERT(code >= 0 && code < 0x100);
  return WaitStatus(code << 8);
}

WaitStatus WaitStatus::for_fatal_sig(int sig) {
  DEBUG_ASSERT(sig >= 1 && sig < 0x80);
  return WaitStatus(sig);
}

WaitStatus WaitStatus::for_stop_sig(int sig) {
  DEBUG_ASSERT(sig >= 1 && sig < 0x80);
  return WaitStatus((sig << 8) | 0x7f);
}

WaitStatus WaitStatus::for_group_sig(int sig, RecordTask* t) {
  DEBUG_ASSERT(sig >= 1 && sig < 0x80);
  int code = (sig << 8) | 0x7f;
  if (t->emulated_ptrace_seized) {
    code |= PTRACE_EVENT_STOP << 16;
  }
  return WaitStatus(code);
}

WaitStatus WaitStatus::for_syscall(RecordTask* t) {
  int code = (SIGTRAP << 8) | 0x7f;
  if (t->emulated_ptrace_options & PTRACE_O_TRACESYSGOOD) {
    code |= 0x80 << 8;
  }
  return WaitStatus(code);
}

WaitStatus WaitStatus::for_ptrace_event(int ptrace_event) {
  DEBUG_ASSERT(ptrace_event >= 1 && ptrace_event < 0x100);
  return WaitStatus((ptrace_event << 16) | (SIGTRAP << 8) | 0x7f);
}

ostream& operator<<(ostream& stream, WaitStatus status) {
  stream << HEX(status.get());
  switch (status.type()) {
    case WaitStatus::EXIT:
      stream << " (EXIT-" << status.exit_code() << ")";
      break;
    case WaitStatus::FATAL_SIGNAL:
      stream << " (FATAL-" << signal_name(status.fatal_sig()) << ")";
      break;
    case WaitStatus::SIGNAL_STOP:
      stream << " (STOP-" << signal_name(status.stop_sig()) << ")";
      break;
    case WaitStatus::GROUP_STOP:
      stream << " (GROUP-STOP-" << signal_name(status.group_stop()) << ")";
      break;
    case WaitStatus::SYSCALL_STOP:
      stream << " (SYSCALL)";
      break;
    case WaitStatus::PTRACE_EVENT:
      stream << " (" << ptrace_event_name(status.ptrace_event()) << ")";
      break;
  }
  return stream;
}

} // namespace rr
