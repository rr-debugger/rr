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

/**
 * This object records the details of an mmapped file region.
 */
class TraceMappedRegion {
public:
  enum Type {
    MMAP,
    SYSV_SHM
  };
  TraceMappedRegion(Type type, const std::string& filename,
                    const struct stat& stat, remote_ptr<void> start,
                    remote_ptr<void> end, uint64_t file_offset_pages = 0)
      : filename(filename),
        stat_(stat),
        start_(start),
        end_(end),
        file_offset_pages(file_offset_pages),
        type_(type) {}

  Type type() const { return type_; }
  const std::string& file_name() const { return filename; }
  const struct stat& stat() const { return stat_; }
  remote_ptr<void> start() const { return start_; }
  remote_ptr<void> end() const { return end_; }
  uint64_t offset_pages() const { return file_offset_pages; }

  size_t size() {
    intptr_t s = end() - start();
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

  uint64_t file_offset_pages;

  Type type_;
};

#endif /* RR_TRACE_MAPPED_REGION_H_ */
