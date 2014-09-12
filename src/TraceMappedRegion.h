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
  TraceMappedRegion(const char* filename, const struct stat& stat,
                    remote_ptr<void> start, remote_ptr<void> end,
                    bool copied = false)
      : copied(copied), stat(stat), start(start), end(end) {
    strncpy(this->filename, filename, sizeof(this->filename));
    this->filename[sizeof(this->filename) - 1] = 0;
  }
  TraceMappedRegion() : copied(false), start(nullptr), end(nullptr) {
    memset(filename, 0, sizeof(filename));
    memset(&stat, 0, sizeof(stat));
  }

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
