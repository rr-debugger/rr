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

WaitStatus::WaitStatus(const siginfo_t &info) : status(0)
{
  if (info.si_code == CLD_EXITED) {
    status = (info.si_status & 0x7f) << 8;
    return;
  }

  if (info.si_code == CLD_KILLED || info.si_code == CLD_DUMPED) {
    status = (info.si_status & 0x7f);
    if (info.si_code == CLD_DUMPED) {
      status |= 0x80;
    }
    return;
  }

  DEBUG_ASSERT(info.si_code == CLD_STOPPED || info.si_code == CLD_TRAPPED);
  status = info.si_status << 8 | 0x7f;
}

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

bool WaitStatus::stopped() const {
  // N.B.: infop distinguishes between ptrace and child stops,
  // but regular waitpid does not.
  // (info.si_code == CLD_TRAPPED || info.si_code == CLD_TRAPPED)
  return WIFSTOPPED(status);
}

int WaitStatus::ptrace_event_code() const {
  return (status >> 16) & 0xff;
}

int WaitStatus::stop_sig_code() const {
  return WSTOPSIG(status);
}

int WaitStatus::stop_sig() const {
  if (!stopped() || ptrace_event_code()) {
    return 0;
  }
  int sig = stop_sig_code();
  if (sig == (SIGTRAP | 0x80)) {
    return 0;
  }
  sig &= ~0x80;
  return sig ? sig : SIGSTOP;
}

int WaitStatus::group_stop() const {
  if (!stopped() || ptrace_event_code() != PTRACE_EVENT_STOP) {
    return 0;
  }
  int sig = stop_sig_code();
  sig &= ~0x80;
  return sig ? sig : SIGSTOP;
}

bool WaitStatus::is_syscall() const {
  if (!stopped() || ptrace_event_code()) {
    return 0;
  }
  return stop_sig_code() == (SIGTRAP | 0x80);
}

int WaitStatus::ptrace_event() const {
  if (!stopped())
    return 0;
  int event = ptrace_event_code();
  return event == PTRACE_EVENT_STOP ? 0 : event;
}

int WaitStatus::ptrace_signal() const {
  return stopped() ? (stop_sig_code() & 0x7f) : 0;
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

template <typename Arch>
void WaitStatus::fill_siginfo(typename Arch::siginfo_t *si, bool ptracer, unsigned ptrace_options)
{
  if (exit_code() >= 0) {
    si->si_code = CLD_EXITED;
    si->_sifields._sigchld.si_status_ = exit_code();
    return;
  }

  if (fatal_sig()) {
    // `waitpid`'s status can't distinguish between CLD_KILLED and CLD_DUMPED.
    // Always use CLD_KILLED for now.
    si->si_code = is_coredumping_signal(fatal_sig()) ? CLD_DUMPED : CLD_KILLED;
    si->_sifields._sigchld.si_status_ = fatal_sig();
    return;
  }

  if (!ptracer) {
    DEBUG_ASSERT(!ptrace_event());
    si->si_code = CLD_STOPPED;
    si->_sifields._sigchld.si_status_ = stop_sig();
    return;
  }

  si->si_code = CLD_TRAPPED;
  if (is_syscall()) {
    if (ptrace_options & PTRACE_O_TRACESYSGOOD) {
      si->_sifields._sigchld.si_status_ = 0x80 | SIGTRAP;
    } else {
      si->_sifields._sigchld.si_status_ = SIGTRAP;
    }
    return;
  }

  si->_sifields._sigchld.si_status_ = status >> 8;
}

template void WaitStatus::fill_siginfo<X86Arch>(X86Arch::siginfo_t*, bool, unsigned);
template void WaitStatus::fill_siginfo<X64Arch>(X64Arch::siginfo_t*, bool, unsigned);
template void WaitStatus::fill_siginfo<ARM64Arch>(ARM64Arch::siginfo_t*, bool, unsigned);

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
