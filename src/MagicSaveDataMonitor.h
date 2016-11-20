/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MAGIC_SAVE_DATA_MONITOR_H_
#define RR_MAGIC_SAVE_DATA_MONITOR_H_

#include "FileMonitor.h"

namespace rr {

/**
 * A FileMonitor to track writes to RR_MAGIC_SAVE_DATA_FD.
 */
class MagicSaveDataMonitor : public FileMonitor {
public:
  MagicSaveDataMonitor() {}

  virtual Type type() { return MagicSaveData; }

  /**
   * During recording, record the written data.
   * During replay, check that the written data matches what was recorded.
   */
  virtual bool needs_offset(Task*, bool) { return false; }
  virtual void did_write(Task* t, const std::vector<Range>& ranges,
                         LazyOffset& offset);
};

} // namespace rr

#endif /* RR_MAGIC_SAVE_DATA_MONITOR_H_ */
