/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_MAPPED_REGION_H_
#define RR_TRACE_MAPPED_REGION_H_

#include <linux/limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include "remote_ptr.h"
#include "TraceFrame.h"

class TraceReader;

class TraceMappedRegion {
public:
  TraceMappedRegion(const std::string& filename, const struct stat& stat,
                    remote_ptr<void> start, remote_ptr<void> end,
                    bool copied = false)
      : filename(filename),
        stat_(stat),
        start_(start),
        end_(end),
        copied_(copied) {}

  const std::string& file_name() const { return filename; }
  const struct stat& stat() const { return stat_; }
  remote_ptr<void> start() const { return start_; }
  remote_ptr<void> end() const { return end_; }
  bool copied() const { return copied_; }

  size_t size() {
    int64_t s = end().as_int() - start().as_int();
    assert(s >= 0);
    return s;
  }

private:
  friend class TraceReader;

  /**
   * TraceReader calls this and fills it in, so we don't need to initialize
   * anything.
   */
  TraceMappedRegion() {}

  std::string filename;
  struct stat stat_;

  /* Bounds of mapped region. */
  remote_ptr<void> start_;
  remote_ptr<void> end_;

  /* Did we save a copy of the mapped region in the trace
   * data? */
  bool copied_;
};

#endif /* RR_TRACE_MAPPED_REGION_H_ */
