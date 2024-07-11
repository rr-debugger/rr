#pragma once
#include "kernel_abi.h"
#include <cstdint>

namespace rr {

struct GdbServerRegisterValue;

using u32 = std::uint32_t;

enum class TargetFeature : u32 {
    Core = 0,
    SSE,
    Linux,
    Segment,
    AVX,
    PKeys
};

class TargetDescription {
    SupportedArch arch;
    std::vector<TargetFeature> target_features;
public:
    explicit TargetDescription(rr::SupportedArch arch, u32 cpu_features) noexcept;
    std::string to_xml() const noexcept;
};
}