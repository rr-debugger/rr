/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MAGIC_SAVE_DATA_MONITOR_H_
#define RR_MAGIC_SAVE_DATA_MONITOR_H_

#include "FileMonitor.h"

/**
 * A FileMonitor to track writes to RR_MAGIC_SAVE_DATA_FD.
 */
class MagicSaveDataMonitor : public FileMonitor {
public:
  MagicSaveDataMonitor() {}

  /**
   * During recording, record the written data.
   * During replay, check that the written data matches what was recorded.
   */
  virtual void did_write(Task* t, const std::vector<Range>& ranges);
};

#endif /* RR_MAGIC_SAVE_DATA_MONITOR_H_ */
