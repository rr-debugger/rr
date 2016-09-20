/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MMAPPED_FILE_MONITOR_H_
#define RR_MMAPPED_FILE_MONITOR_H_

#include "EmuFs.h"
#include "FileMonitor.h"

#include <sys/stat.h>

namespace rr {

/**
 * A FileMonitor to track writes to files that are mmapped in so they can be
 * replayed.
 */
class MmappedFileMonitor : public FileMonitor {
public:
  MmappedFileMonitor(Task* t, int fd);
  MmappedFileMonitor(Task* t, EmuFile::shr_ptr f);

  virtual Type type() { return Mmapped; }

  /**
   * During recording, note writes to mapped segments.
   */
  virtual void did_write(Task* t, const std::vector<Range>& ranges,
                         int64_t offset);

private:
  bool extant_;
  dev_t device_;
  ino_t inode_;
};

} // namespace rr

#endif /* RR_MMAPPED_FILE_MONITOR_H_ */
