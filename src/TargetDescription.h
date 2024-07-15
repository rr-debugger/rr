#pragma once
#include "kernel_abi.h"
#include <cstdint>

namespace rr {

struct GdbServerRegisterValue;

enum class TargetFeature : uint32_t {
  Core = 0,
  SSE,
  Linux,
  Segment,
  AVX,
  PKeys,
  FPU,
};

class TargetDescription {
  SupportedArch arch;
  std::vector<TargetFeature> target_features;

public:
  explicit TargetDescription(rr::SupportedArch arch, uint32_t cpu_features);
  std::string to_xml() const;
};
} // namespace rr