/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MEMORY_RANGE_H_
#define RR_MEMORY_RANGE_H_

#include "core.h"
#include "remote_ptr.h"

namespace rr {

/**
 * Range of memory addresses that can be used as a std::map key.
 */
class MemoryRange {
public:
  MemoryRange() {}
  MemoryRange(remote_ptr<void> addr, size_t num_bytes)
      : start_(addr), end_(addr + num_bytes) {
    DEBUG_ASSERT(start_ <= end_);
  }
  MemoryRange(remote_ptr<void> addr, remote_ptr<void> end)
      : start_(addr), end_(end) {
    DEBUG_ASSERT(start_ <= end);
  }
  MemoryRange(const MemoryRange&) = default;
  MemoryRange& operator=(const MemoryRange&) = default;

  bool operator==(const MemoryRange& o) const {
    return start_ == o.start_ && end_ == o.end_;
  }
  bool operator<(const MemoryRange& o) const {
    return start_ != o.start_ ? start_ < o.start_ : end_ < o.end_;
  }

  /**
   * Return true iff |o| is an address range fully contained by
   * this.
   */
  bool contains(const MemoryRange& o) const {
    return start_ <= o.start_ && o.end_ <= end_;
  }
  bool contains(remote_ptr<void> p) const { return start_ <= p && p < end_; }

  bool intersects(const MemoryRange& other) const {
    remote_ptr<void> s = std::max(start_, other.start_);
    remote_ptr<void> e = std::min(end_, other.end_);
    return s < e;
  }

  MemoryRange intersect(const MemoryRange& other) const {
    remote_ptr<void> s = std::max(start_, other.start_);
    remote_ptr<void> e = std::min(end_, other.end_);
    return MemoryRange(s, std::max(s, e));
  }

  remote_ptr<void> start() const { return start_; }
  remote_ptr<void> end() const { return end_; }
  size_t size() const { return end_ - start_; }

  // XXX DO NOT USE
  void update_start(remote_ptr<void> s) const {
    const_cast<MemoryRange*>(this)->start_ = s;
  }

private:
  remote_ptr<void> start_;
  remote_ptr<void> end_;
};

inline std::ostream& operator<<(std::ostream& o, const MemoryRange& m) {
  o << m.start() << "-" << m.end();
  return o;
}

} // namespace rr

#endif /* RR_MEMORY_RANGE_H_ */
