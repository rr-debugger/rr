/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "TargetDescription.h"

#include <sstream>

#include "GdbServerConnection.h"
#include "kernel_abi.h"
#include "util.h"

using namespace std;

namespace rr {

class FeatureStream {
public:
  string result() { return stream.str(); }

  template <typename Any>
  friend FeatureStream& operator<<(FeatureStream& stream, Any any);

private:
  stringstream stream;
  const char* arch_prefix;
};

template <typename Any>
FeatureStream& operator<<(FeatureStream& stream, Any any) {
  stream.stream << any;
  return stream;
}

template <>
FeatureStream& operator<<(FeatureStream& stream, rr::SupportedArch arch) {
  stream << "<architecture>";
  switch (arch) {
    case rr::x86:
      stream << "i386";
      stream.arch_prefix = "32bit-";
      break;
    case rr::x86_64:
      stream << "i386:x86-64";
      stream.arch_prefix = "64bit-";
      break;
    case rr::aarch64:
      stream << "aarch64";
      stream.arch_prefix = "aarch64-";
      break;
  }
  stream << "</architecture>\n";
  return stream;
}

template <>
FeatureStream& operator<<(FeatureStream& stream, TargetFeature feature) {
  DEBUG_ASSERT(stream.arch_prefix != nullptr &&
               "No architecture has been provided to description");
  stream << R"(  <xi:include href=")" << stream.arch_prefix;
  switch (feature) {
    case TargetFeature::Core:
      stream << "core.xml";
      break;
    case TargetFeature::Linux:
      stream << "linux.xml";
      break;
    case TargetFeature::SSE:
      stream << "sse.xml";
      break;
    case TargetFeature::AVX:
      stream << "avx.xml";
      break;
    case TargetFeature::AVX512:
      stream << "avx512.xml";
      break;
    case TargetFeature::PKeys:
      stream << "pkeys.xml";
      break;
    case TargetFeature::Segment:
      stream << "seg.xml";
      break;
    case TargetFeature::FPU:
      stream << "fpu.xml";
      break;
    case TargetFeature::PAuth:
      stream << "pauth.xml";
      break;
  }
  stream << R"("/>)" << '\n';
  return stream;
}

static void get_x86_cpu_features_from_cpuid(const vector<CPUIDRecord>& cpuid_records,
    vector<TargetFeature>& target_features) {
  auto cpuid_data =
      find_cpuid_record(cpuid_records, CPUID_GETEXTENDEDFEATURES, 0);
  bool pku = cpuid_data != nullptr && (cpuid_data->out.ecx & PKU_FEATURE_FLAG);
  bool avx512 = cpuid_data != nullptr && (cpuid_data->out.ebx & AVX_512_FOUNDATION_FLAG);
  cpuid_data = find_cpuid_record(cpuid_records, CPUID_GETFEATURES, 0);
  unsigned int AVX_cpuid_flags = AVX_FEATURE_FLAG | OSXSAVE_FEATURE_FLAG;
  bool avx = cpuid_data != nullptr && (cpuid_data->out.ecx & AVX_cpuid_flags) == AVX_cpuid_flags;

  if (avx) {
    target_features.push_back(TargetFeature::AVX);
  }
  if (avx512) {
    target_features.push_back(TargetFeature::AVX512);
  }
  if (pku) {
    target_features.push_back(TargetFeature::PKeys);
  }
}

static void get_x86_cpu_features(const TraceReader* trace,
    vector<TargetFeature>& target_features) {
  if (trace == nullptr) {
    return get_x86_cpu_features_from_cpuid(all_cpuid_records(),
        target_features);
  }
  return get_x86_cpu_features_from_cpuid(trace->cpuid_records(),
        target_features);
}

static void get_arm_cpu_features(const TraceReader* trace,
    vector<TargetFeature>& target_features) {
  bool pauth;
  if (trace != nullptr) {
    pauth = trace->aarch64_pauth();
  } else {
    pauth = aarch64_pauth_enabled();
  }
  if (pauth) {
    target_features.push_back(TargetFeature::PAuth);
  }
}

TargetDescription::TargetDescription(rr::SupportedArch arch,
                                     const TraceReader* trace)
    : arch(arch) {
  switch (arch) {
    case rr::x86:
      target_features.push_back(TargetFeature::Core);
      target_features.push_back(TargetFeature::SSE);
      target_features.push_back(TargetFeature::Linux);
      get_x86_cpu_features(trace, target_features);
      break;
    case rr::x86_64:
      target_features.push_back(TargetFeature::Core);
      target_features.push_back(TargetFeature::SSE);
      target_features.push_back(TargetFeature::Linux);
      target_features.push_back(TargetFeature::Segment);
      get_x86_cpu_features(trace, target_features);
      break;
    case rr::aarch64:
      target_features.push_back(TargetFeature::Core);
      target_features.push_back(TargetFeature::FPU);
      get_arm_cpu_features(trace, target_features);
      break;
  }
}

static const char header[] = R"(<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target>
)";

string TargetDescription::to_xml() const {
  FeatureStream fs;
  fs << header << arch << "<osabi>GNU/Linux</osabi>\n";
  for (const auto feature : target_features) {
    fs << feature;
  }
  fs << "</target>";

  return fs.result();
}

} // namespace rr