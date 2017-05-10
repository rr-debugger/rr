/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROC_FD_DIR_MONITOR_H_
#define RR_PROC_FD_DIR_MONITOR_H_

#include "FileMonitor.h"
#include "TaskishUid.h"

namespace rr {

/**
 * A FileMonitor to intercept enumerations of /proc/<pid>/fd so that entries
 * for rr's private fds can be hidden when <pid> is a tracee.
 */
class ProcFdDirMonitor : public FileMonitor {
public:
  ProcFdDirMonitor(Task* t, const std::string& pathname);

  virtual Type type() override { return ProcFd; }

  virtual void filter_getdents(RecordTask* t) override;

private:
  // 0 if this doesn't object doesn't refer to a tracee's proc-mem.
  TaskUid tuid;
};

} // namespace rr

#endif /* RR_PROC_FD_DIR_MONITOR_H_ */
