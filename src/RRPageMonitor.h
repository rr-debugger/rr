/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RR_PAGE_MONITOR_H_
#define RR_RR_PAGE_MONITOR_H_

#include "FileMonitor.h"
#include "TraceStream.h"

namespace rr {

/**
 * RRPageMonitor gets installed upon any open of the librrpage.so preload library.
 * If this file gets mmaped, rr will attempt to map it to coincide with the
 * required fixed location for the rr page.
 */
class RRPageMonitor : public FileMonitor {
public:
  RRPageMonitor() : FileMonitor() {};

  virtual Type type() const override { return RRPage; }
};

static_assert(TraceReader::SpecialLibRRpage != 0,
  "Remember to delete this if support for the quirk is ever dropped");

} // namespace rr

#endif /* RR_RR_PAGE_MONITOR_H_ */
