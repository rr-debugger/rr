/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TARGET_DESCRIPTION_H_
#define RR_TARGET_DESCRIPTION_H_

#include <cstdint>

#include "kernel_abi.h"
#include "TraceStream.h"

namespace rr {

enum class TargetFeature : uint8_t {
  Core = 0,
  SSE,
  Linux,
  Segment,
  AVX,
  AVX512,
  PKeys,
  FPU,
  PAuth,
};

class TargetDescription {
public:
  explicit TargetDescription(rr::SupportedArch arch, const TraceReader* trace);
  uint32_t cpu_features() const {
    uint32_t result = 0;
    for (TargetFeature f : target_features) {
      result |= 1 << static_cast<uint32_t>(f);
    }
    return result;
  }
  std::string to_xml() const;

private:
  SupportedArch arch;
  std::vector<TargetFeature> target_features;
};
} // namespace rr

#endif /* RR_TARGET_DESCRIPTION_H_ */