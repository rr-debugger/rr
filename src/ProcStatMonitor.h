/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROC_STAT_MONITOR_H_
#define RR_PROC_STAT_MONITOR_H_

#include "FileMonitor.h"

namespace rr {

/**
 * A FileMonitor to intercept /proc/stat in order to pretend to the
 * tracee that it only has the CPUs that rr is willing to give it.
 * This is necessary on top of the SysCpuMonitor, because some versions
 * of glibc have bugs that cause it to fail to parse the
 * /sys/devices/system/cpu/online format, causing them to fallback to /proc/stat
 */
class ProcStatMonitor : public FileMonitor {
public:
  ProcStatMonitor(Task* t, const std::string& pathname);

  virtual Type type() const override { return ProcStat; }

  bool emulate_read(RecordTask* t, const std::vector<Range>& ranges,
                    LazyOffset&, uint64_t* result) override;

private:
  void serialize_type(
      pcp::FileMonitor::Builder& builder) const noexcept override;
  std::string data;
};

} // namespace rr

#endif /* RR_PROC_STAT_MONITOR_H_ */
