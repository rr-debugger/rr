/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PRESERVE_FILE_MONITOR_H_
#define RR_PRESERVE_FILE_MONITOR_H_

#include "FileMonitor.h"

/**
 * A FileMonitor that does no monitoring of I/O itself, but prevents the file
 * descriptor from being closed (except via privileged syscalls made by
 * preload.c).
 *
 * The mere existence of this monitor disables syscall buffering for the fd, so
 * we get syscall traps for close() etc on the fd. Then
 * rec_prepare_syscall_arch calls allow_close() to check whether closing is
 * allowed.
 */
class PreserveFileMonitor : public FileMonitor {
public:
  PreserveFileMonitor() {}
  virtual bool allow_close() { return false; }
};

#endif /* RR_PRESERVE_FILE_MONITOR_H_ */
