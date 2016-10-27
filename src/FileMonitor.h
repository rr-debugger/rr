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

  enum Type {
    Base,
    MagicSaveData,
    Mmapped,
    Preserve,
    ProcFd,
    ProcMem,
    Stdio,
    VirtualPerfCounter,
  };

  virtual Type type() { return Base; }

  /**
   * Overriding this to return true will cause close() (and related fd-smashing
   * operations such as dup2) to return EBADF, and hide it from the tracee's
   * /proc/pid/fd/
   */
  virtual bool is_rr_fd() { return false; }

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

  /**
   * Encapsulates the offset at which to read or write. Computing this may be
   * an expensive operation if the offset is implicit (i.e. is taken from the
   * file descriptor), so we only do it if we actually need to look at the
   * offset.
   */
  class LazyOffset {
  public:
    LazyOffset(Task* t, const Registers& regs, int64_t syscallno)
        : t(t), regs(regs), syscallno(syscallno) {}
    int64_t retrieve(bool needed_for_replay);

  private:
    Task* t;
    const Registers& regs;
    int64_t syscallno;
  };

  virtual void did_write(Task*, const std::vector<Range>&, LazyOffset&) {}

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
  virtual bool emulate_read(RecordTask*, const std::vector<Range>&, LazyOffset&,
                            uint64_t*) {
    return false;
  }

  /**
   * Allows the FileMonitor to rewrite the output of a getdents/getdents64 call
   * if desired.
   */
  virtual void filter_getdents(RecordTask*) {}
};

} // namespace rr

#endif /* RR_FILE_MONITOR_H_ */
