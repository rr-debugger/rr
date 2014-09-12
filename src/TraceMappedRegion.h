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
      : stat(stat), start(start), end(end), copied_(copied) {
    strncpy(this->filename, filename, sizeof(this->filename));
    this->filename[sizeof(this->filename) - 1] = 0;
  }
  TraceMappedRegion() : start(nullptr), end(nullptr), copied_(false) {
    memset(filename, 0, sizeof(filename));
    memset(&stat, 0, sizeof(stat));
  }

  bool copied() const { return copied_; }
  const char* file_name() const { return filename; }

  size_t size() {
    int64_t s = end.as_int() - start.as_int();
    assert(s >= 0);
    return s;
  }

  friend TraceIfstream& operator>>(TraceIfstream& tif, TraceMappedRegion& map);

  char filename[PATH_MAX];
  struct stat stat;

  /* Bounds of mapped region. */
  remote_ptr<void> start;
  remote_ptr<void> end;

  /* Did we save a copy of the mapped region in the trace
   * data? */
  bool copied_;
};

#endif /* RR_TRACE_MAPPED_REGION_H_ */
