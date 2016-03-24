/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_WAIT_STATUS_H_
#define RR_WAIT_STATUS_H_

#include <memory>
#include <vector>

namespace rr {

class WaitStatus {
public:
  WaitStatus(int status = 0) : status(status) {}

  enum Type {
    // Task exited normally.
    EXIT,
    // Task exited due to fatal signal.
    FATAL_SIGNAL,
    // Task is stopped due to a signal.
    STOP_SIGNAL,
    // Task is stopped due to a syscall-stop signal triggered by PTRACE_SYSCALL
    // and PTRACE_O_TRACESYSGOOD.
    SYSCALL,
    // Task is stopped due to a PTRACE_EVENT_*.
    PTRACE_EVENT
  };

  Type type() const;

  // Exit code if type() == EXIT, otherwise -1.
  int exit_code() const;
  // Fatal signal if type() == FATAL_SIGNAL, otherwise zero.
  int fatal_sig() const;
  // Stop signal if type() == STOP_SIGNAL, otherwise zero.
  int stop_sig() const;
  bool is_syscall() const;
  // ptrace event if type() == PTRACE_EVENT, otherwise zero.
  int ptrace_event() const;

  int get() const { return status; }

private:
  int status;
};

std::ostream& operator<<(std::ostream& stream, WaitStatus status);

} // namespace rr

#endif /* RR_WAIT_STATUS_H_ */
