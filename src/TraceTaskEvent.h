/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_TASK_EVENT_H_
#define RR_TRACE_TASK_EVENT_H_

#include <string>
#include <vector>

#include "Event.h"
#include "ExtraRegisters.h"
#include "PerfCounters.h"
#include "TraceFrame.h"
#include "WaitStatus.h"
#include "core.h"

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

  static TraceTaskEvent for_clone(pid_t tid, pid_t parent_tid, pid_t own_ns_tid,
                                  int clone_flags) {
    TraceTaskEvent result(CLONE, tid);
    result.parent_tid_ = parent_tid;
    result.own_ns_tid_ = own_ns_tid;
    result.clone_flags_ = clone_flags;
    return result;
  }
  static TraceTaskEvent for_exec(pid_t tid, const std::string& file_name,
                                 const std::vector<std::string> cmd_line) {
    TraceTaskEvent result(EXEC, tid);
    result.file_name_ = file_name;
    result.cmd_line_ = cmd_line;
    result.exe_base_ = nullptr;
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
    DEBUG_ASSERT(type() == CLONE);
    return parent_tid_;
  }
  pid_t own_ns_tid() const {
    DEBUG_ASSERT(type() == CLONE);
    return own_ns_tid_;
  }
  int clone_flags() const {
    DEBUG_ASSERT(type() == CLONE);
    return clone_flags_;
  }
  const std::string& file_name() const {
    DEBUG_ASSERT(type() == EXEC);
    return file_name_;
  }
  const std::vector<std::string>& cmd_line() const {
    DEBUG_ASSERT(type() == EXEC);
    return cmd_line_;
  }
  // May be zero when not present in older trace versions
  remote_ptr<void> exe_base() const {
    DEBUG_ASSERT(type() == EXEC);
    return exe_base_;
  }
  void set_exe_base(remote_ptr<void> ptr) {
    DEBUG_ASSERT(type() == EXEC);
    exe_base_ = ptr;
  }
  WaitStatus exit_status() const {
    DEBUG_ASSERT(type() == EXIT);
    return exit_status_;
  }

private:
  friend class TraceReader;
  friend class TraceWriter;

  Type type_;
  pid_t tid_;
  pid_t parent_tid_;                  // CLONE only
  pid_t own_ns_tid_;                  // CLONE only
  int clone_flags_;                   // CLONE only
  std::string file_name_;             // EXEC only
  std::vector<std::string> cmd_line_; // EXEC only
  remote_ptr<void> exe_base_;         // EXEC only
  WaitStatus exit_status_;            // EXIT only
};

} // namespace rr

#endif /* RR_TRACE_TASK_EVENT_H_ */
