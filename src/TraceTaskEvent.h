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
#include "WaitStatus.h"

namespace rr {

class TraceReader;
class TraceWriter;

class TraceTaskEvent {
public:
  enum Type {
    NONE,
    CLONE, // created by clone(2), fork(2), vfork(2) syscalls
    EXEC,
    EXIT
  };

  TraceTaskEvent(Type type = NONE, pid_t tid = 0) : type_(type), tid_(tid) {}

  static TraceTaskEvent for_clone(pid_t tid, pid_t parent_tid,
                                  uint32_t clone_flags) {
    TraceTaskEvent result(CLONE, tid);
    result.parent_tid_ = parent_tid;
    result.clone_flags_ = clone_flags;
    return result;
  }
  static TraceTaskEvent for_exec(pid_t tid, const std::string& file_name,
                                 const std::vector<std::string> cmd_line) {
    TraceTaskEvent result(EXEC, tid);
    result.file_name_ = file_name;
    result.cmd_line_ = cmd_line;
    return result;
  }
  static TraceTaskEvent for_exit(pid_t tid, WaitStatus exit_status) {
    TraceTaskEvent result(EXIT, tid);
    result.exit_status_ = exit_status;
    return result;
  }

  Type type() const { return type_; }
  pid_t tid() const { return tid_; }
  pid_t parent_tid() const {
    assert(type() == CLONE);
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
  WaitStatus exit_status() const {
    assert(type() == EXIT);
    return exit_status_;
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
  WaitStatus exit_status_;            // EXIT only
};

} // namespace rr

#endif /* RR_TRACE_TASK_EVENT_H_ */
