/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_TASK_EVENT_H_
#define RR_TRACE_TASK_EVENT_H_

#include <assert.h>

#include <string>
#include <vector>

#include "Event.h"
#include "ExtraRegisters.h"
#include "PerfCounters.h"
#include "TraceFrame.h"

namespace rr {

class TraceReader;
class TraceWriter;

class TraceTaskEvent {
public:
  TraceTaskEvent(pid_t tid, pid_t parent_tid)
      : type_(FORK), tid_(tid), parent_tid_(parent_tid) {}
  TraceTaskEvent(pid_t tid, pid_t parent_tid, uint32_t clone_flags)
      : type_(CLONE),
        tid_(tid),
        parent_tid_(parent_tid),
        clone_flags_(clone_flags) {}
  TraceTaskEvent(pid_t tid, const std::string& file_name,
                 const std::vector<std::string> cmd_line)
      : type_(EXEC), tid_(tid), file_name_(file_name), cmd_line_(cmd_line) {}
  TraceTaskEvent(pid_t tid) : type_(EXIT), tid_(tid) {}
  TraceTaskEvent() : type_(NONE) {}

  enum Type {
    NONE,
    CLONE, // created by clone(2) syscall
    FORK,  // created by fork(2) syscall
    EXEC,
    EXIT
  };

  Type type() const { return type_; }
  pid_t tid() const { return tid_; }
  pid_t parent_tid() const {
    assert(type() == CLONE || type() == FORK);
    return parent_tid_;
  }
  uintptr_t clone_flags() const {
    assert(type() == CLONE);
    return clone_flags_;
  }
  const std::string& file_name() const {
    assert(type() == EXEC);
    return file_name_;
  }
  const std::vector<std::string>& cmd_line() const {
    assert(type() == EXEC);
    return cmd_line_;
  }
  const std::vector<int>& fds_to_close() const {
    assert(type() == EXEC);
    return fds_to_close_;
  }

  bool is_fork() const {
    return type() == FORK || (type() == CLONE && !(clone_flags() & CLONE_VM));
  }

  void set_fds_to_close(const std::vector<int> fds) {
    assert(type() == EXEC);
    fds_to_close_ = fds;
  }

private:
  friend class TraceReader;
  friend class TraceWriter;

  Type type_;
  pid_t tid_;
  pid_t parent_tid_;                  // CLONE only
  uintptr_t clone_flags_;             // CLONE only
  std::string file_name_;             // EXEC only
  std::vector<std::string> cmd_line_; // EXEC only
  std::vector<int> fds_to_close_;     // EXEC only
};

} // namespace rr

#endif /* RR_TRACE_TASK_EVENT_H_ */
