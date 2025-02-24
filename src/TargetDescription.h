/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TARGET_DESCRIPTION_H_
#define RR_TARGET_DESCRIPTION_H_

#include <cstdint>

#include "kernel_abi.h"

using namespace std;

namespace rr {

enum class TargetFeature : uint32_t {
  Core = 0,
  SSE,
  Linux,
  Segment,
  AVX,
  AVX512,
  PKeys,
  FPU,
};

class TargetDescription {
public:
  explicit TargetDescription(rr::SupportedArch arch, uint32_t cpu_features);
  string to_xml() const;

private:
  SupportedArch arch;
  vector<TargetFeature> target_features;
};
} // namespace rr

#endif /* RR_TARGET_DESCRIPTION_H_ */