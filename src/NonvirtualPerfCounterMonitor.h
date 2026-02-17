/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_NONVIRTUAL_PERF_COUNTER_MONITOR_H_
#define RR_NONVIRTUAL_PERF_COUNTER_MONITOR_H_

#include "FileMonitor.h"

namespace rr {

/**
 * A FileMonitor attached to (nonvirtualized) perf counter fds. This just stops those fds from
 * being mmaped.
 */
class NonvirtualPerfCounterMonitor : public FileMonitor {
public:
  NonvirtualPerfCounterMonitor() {}

  virtual Type type() const override { return NonvirtualPerfCounter; }
};

} // namespace rr

#endif /* RR_NONVIRTUAL_PERF_COUNTER_MONITOR_H_ */
