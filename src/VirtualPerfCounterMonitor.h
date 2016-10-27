/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_VIRTUAL_PERF_COUNTER_MONITOR_H_
#define RR_VIRTUAL_PERF_COUNTER_MONITOR_H_

#include "FileMonitor.h"
#include "TaskishUid.h"

struct perf_event_attr;

namespace rr {

/**
 * A FileMonitor to
 */
class VirtualPerfCounterMonitor : public FileMonitor {
public:
  static bool should_virtualize(const struct perf_event_attr& attr);

  VirtualPerfCounterMonitor(Task* t, Task* target,
                            const struct perf_event_attr& attr);

  virtual Type type() override { return VirtualPerfCounter; }

  virtual bool emulate_ioctl(RecordTask* t, uint64_t* result) override;
  virtual bool emulate_fcntl(RecordTask* t, uint64_t* result) override;
  virtual bool emulate_read(RecordTask* t, const std::vector<Range>& ranges,
                            LazyOffset& offset, uint64_t* result) override;

private:
  Ticks initial_ticks;
  TaskUid target_tuid;
  pid_t owner_tid;
  int flags;
  int sig;
  bool enabled;
};

} // namespace rr

#endif /* RR_VIRTUAL_PERF_COUNTER_MONITOR_H_ */
