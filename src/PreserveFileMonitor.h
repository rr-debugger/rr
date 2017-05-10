/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PRESERVE_FILE_MONITOR_H_
#define RR_PRESERVE_FILE_MONITOR_H_

#include "FileMonitor.h"

namespace rr {

/**
 * A FileMonitor that does no monitoring of I/O itself, but prevents the file
 * descriptor from being closed (except via privileged syscalls made by
 * preload.c) or seen in /proc/pid/fd/.
 *
 * The mere existence of this monitor disables syscall buffering for the fd, so
 * we get syscall traps for close() etc on the fd. Then
 * rec_prepare_syscall_arch calls allow_close() to check whether closing is
 * allowed.
 */
class PreserveFileMonitor : public FileMonitor {
public:
  PreserveFileMonitor() {}
  virtual Type type() override { return Preserve; }
  virtual bool is_rr_fd() override { return true; }
};

} // namespace rr

#endif /* RR_PRESERVE_FILE_MONITOR_H_ */
