/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_STDIO_MONITOR_H_
#define RR_STDIO_MONITOR_H_

#include "FileMonitor.h"

/**
 * A FileMonitor to track stdout/stderr fds.
 * Currently does nothing other than prevent syscallbuf from buffering output
 * to those fds.
 */
class StdioMonitor : public FileMonitor {
public:
  StdioMonitor() {}

  /**
   * Make writes to stdout/stderr blocking, to avoid nondeterminism in the
   * order in which the kernel actually performs such writes.
   * This theoretically introduces the possibility of deadlock between rr's
   * tracee and some external program reading rr's output
   * via a pipe ... but that seems unlikely to bite in practice.
   */
  virtual Switchable will_write(Task* t) { return PREVENT_SWITCH; }
};

#endif /* RR_STDIO_MONITOR_H_ */
