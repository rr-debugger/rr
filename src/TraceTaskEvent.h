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

class TraceReader;
class TraceWriter;

class TraceTaskEvent {
public:
  TraceTaskEvent(pid_t pid, pid_t parent_pid, uint32_t clone_flags)
      : type_(CLONE),
        pid_(pid),
        parent_pid_(parent_pid),
        clone_flags_(clone_flags) {}
  TraceTaskEvent(pid_t pid, const std::string& file_name,
                 const std::vector<std::string> cmd_line)
      : type_(EXEC), pid_(pid), file_name_(file_name), cmd_line_(cmd_line) {}
  TraceTaskEvent(pid_t pid) : type_(EXIT), pid_(pid) {}
  TraceTaskEvent() : type_(NONE) {}

  enum Type {
    NONE,
    CLONE,
    EXEC,
    EXIT
  };

  Type type() const { return type_; }
  pid_t pid() const { return pid_; }
  pid_t parent_pid() const {
    assert(type() == CLONE);
    return parent_pid_;
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

private:
  friend class TraceReader;
  friend class TraceWriter;

  Type type_;
  pid_t pid_;
  pid_t parent_pid_;                  // CLONE only
  uintptr_t clone_flags_;             // CLONE only
  std::string file_name_;             // EXEC only
  std::vector<std::string> cmd_line_; // EXEC only
};

#endif /* RR_TRACE_TASK_EVENT_H_ */
