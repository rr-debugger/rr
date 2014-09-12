/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_MAPPED_REGION_H_
#define RR_TRACE_MAPPED_REGION_H_

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "remote_ptr.h"
#include "TraceFrame.h"

struct TraceMappedRegion {
  /* Global trace time when this region was mapped. */
  TraceFrame::Time time;
  pid_t tid;
  /* Did we save a copy of the mapped region in the trace
   * data? */
  bool copied;

  char filename[PATH_MAX];
  struct stat stat;

  /* Bounds of mapped region. */
  remote_ptr<void> start;
  remote_ptr<void> end;

  size_t size() {
    int64_t s = static_cast<uint8_t*>(static_cast<void*>(end)) -
                static_cast<uint8_t*>(static_cast<void*>(start));
    assert(s >= 0);
    return s;
  }
};

#endif /* RR_TRACE_MAPPED_REGION_H_ */
