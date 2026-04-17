/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_ODIRECT_MONITOR_H_
#define RR_ODIRECT_MONITOR_H_

#include "FileMonitor.h"
#include "TraceStream.h"

namespace rr {

/**
 * ODirectFileMonitor gets installed upon any use of O_DIRECT.
 * This monitor can get replaced by an MMappedFileMonitor if the
 * file is later MAP_SHARED.
 */
class ODirectFileMonitor : public FileMonitor {
public:
  ODirectFileMonitor() : FileMonitor() {};

  virtual Type type() const override { return ODirect; }
};

} // namespace rr

#endif /* RR_ODIRECT_MONITOR_H_ */
