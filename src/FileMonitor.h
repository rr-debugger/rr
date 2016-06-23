/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FILE_MONITOR_H_
#define RR_FILE_MONITOR_H_

class Task;

#include <stdint.h>
#include <stdlib.h>

#include <memory>
#include <vector>

#include "util.h"

namespace rr {

class RecordTask;
class Registers;

class FileMonitor {
public:
  typedef std::shared_ptr<FileMonitor> shr_ptr;

  virtual ~FileMonitor() {}

  /**
   * Overriding this to return false will cause close() (and related fd-smashing
   * operations such as dup2) to return EBADF.
   */
  virtual bool allow_close() { return true; }

  /**
   * Notification that task |t| is about to write |data| bytes of length
   * |length| to the file.
   * In general writes can block, and concurrent blocking writes to the same
   * file may race so that the kernel performs writes out of order
   * with respect to will_write notifications.
   * If it is known that the write cannot block (or that blocking all of rr
   * on it is OK), this notification can return PREVENT_SWITCH to make the
   * write a blocking write. This ensures that writes are performed in the order
   * of will_write notifications.
   */
  virtual Switchable will_write(Task*) { return ALLOW_SWITCH; }
  /**
   * Notification that task |t| wrote to the file descriptor.
   * Due to races, if will_write did not return PREVENT_SWITCH, it's possible
   * that the data in the buffers is not what was actually written.
   */
  struct Range {
    remote_ptr<void> data;
    size_t length;
    Range(remote_ptr<void> data, size_t length) : data(data), length(length) {}
  };
  virtual void did_write(Task*, const std::vector<Range>&, int64_t) {}

  /**
   * Return true if the ioctl should be fully emulated. If so the result
   * is stored in the last parameter.
   * Only called during recording.
   */
  virtual bool emulate_ioctl(RecordTask*, uint64_t*) { return false; }

  /**
   * Return true if the fcntl should should be fully emulated. If so the
   * result is stored in the last parameter.
   * Only called during recording.
   */
  virtual bool emulate_fcntl(RecordTask*, uint64_t*) { return false; }

  /**
   * Return true if the read should should be fully emulated. If so the
   * result is stored in the last parameter. The emulation should write to the
   * task's memory ranges.
   * Only called during recording.
   */
  virtual bool emulate_read(RecordTask*, const std::vector<Range>&, int64_t,
                            uint64_t*) {
    return false;
  }
};

} // namespace rr

#endif /* RR_FILE_MONITOR_H_ */
