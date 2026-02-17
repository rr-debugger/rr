/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PID_FD_MONITOR_H_
#define RR_PID_FD_MONITOR_H_

#include "FdTable.h"
#include "FileMonitor.h"
#include "TaskishUid.h"

struct perf_event_attr;

namespace rr {

class Session;

/**
 * A FileMonitor to handle pidfd fds
 */
class PidFdMonitor : public FileMonitor {
public:
  PidFdMonitor(TaskUid tuid)
    : tuid(tuid) {}

  virtual Type type() const override { return PidFd; }

  static PidFdMonitor* get(FdTable* fd_table, int fd);

  FdTable::shr_ptr fd_table(Session& session) const;

private:
  // 0 if this doesn't object doesn't refer to a tracee's proc-mem.
  TaskUid tuid;
};

} // namespace rr

#endif /* RR_PID_FD_MONITOR_H_ */
