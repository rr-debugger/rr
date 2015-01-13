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
};

#endif /* RR_STDIO_MONITOR_H_ */
