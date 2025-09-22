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
  MmappedFileMonitor(bool dead, dev_t device, ino_t inode) noexcept;

  virtual Type type() const override { return Mmapped; }
  void revive() { dead_ = false; }
  // If this write could potentially affect memory we need to PREVENT_SWITCH,
  // since the timing of the write is otherwise unpredictable from our
  // perspective.
  virtual Switchable will_write(Task*) override {
    return dead_ ? ALLOW_SWITCH : PREVENT_SWITCH;
  }

  /**
   * During recording, note writes to mapped segments.
   */
  virtual void did_write(Task* t, const std::vector<Range>& ranges,
                         LazyOffset& offset) override;

private:
  void serialize_type(
      pcp::FileMonitor::Builder& builder) const noexcept override;
  // Whether this monitor is still actively monitoring
  bool dead_;
  dev_t device_;
  ino_t inode_;
};

} // namespace rr

#endif /* RR_MMAPPED_FILE_MONITOR_H_ */
