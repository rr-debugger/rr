/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SYS_CPU_MONITOR_H_
#define RR_SYS_CPU_MONITOR_H_

#include "FileMonitor.h"
#include "TaskishUid.h"

namespace rr {

/**
 * A FileMonitor to intercept /sys/devices/system/cpu/online (and potentially
 * other files in that directory in the future) in order to pretend to the
 * tracee that it only has the CPUs that rr is willing to give it
 */
class SysCpuMonitor : public FileMonitor {
public:
  SysCpuMonitor(Task* t, const std::string& pathname);

  virtual Type type() override { return SysCpu; }

  bool emulate_read(RecordTask* t, const std::vector<Range>& ranges,
                    LazyOffset&, uint64_t* result) override;
};

} // namespace rr

#endif /* RR_SYS_CPU_MONITOR_H_ */
