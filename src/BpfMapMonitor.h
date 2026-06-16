/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_BPF_MAP_MONITOR_H_
#define RR_BPF_MAP_MONITOR_H_

#include "FileMonitor.h"

namespace rr {

/**
 * A FileMonitor attached to BPF map fds to record their key and value size.
 */
class BpfMapMonitor : public FileMonitor {
public:
  BpfMapMonitor(uint64_t key_size, uint64_t value_size) : key_size_(key_size), value_size_(value_size) {}

  virtual Type type() const override { return BpfMap; }

  uint64_t key_size() const { return key_size_; }
  uint64_t value_size() const { return value_size_; }

private:
  virtual void serialize_type(
      pcp::FileMonitor::Builder& builder) const noexcept override {
    auto bpf = builder.initBpf();
    bpf.setKeySize(key_size_);
    bpf.setValueSize(value_size_);
  }

  uint64_t key_size_;
  uint64_t value_size_;
};

} // namespace rr

#endif /* RR_BPF_MAP_MONITOR_H_ */
