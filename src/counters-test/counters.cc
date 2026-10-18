#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#define CHECK(condition) \
  do { \
    if (!(condition)) { \
      fprintf(stderr, "CHECK '%s' failed at %s:%d (errno=%d)\n", #condition, __FILE__, __LINE__, errno); \
      abort(); \
    } \
  } while (0)

__attribute__((format(printf, 1, 2)))
static void die(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  fputc('\n', stderr);
  abort();
}

/* ==== Copied from PerfCounters.cc ==== */

/*
 * Find out the cpu model using the cpuid instruction.
 * Full list of CPUIDs at http://sandpile.org/x86/cpuid.htm
 * Another list at
 * http://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers
 */
enum CpuMicroarch {
  UnknownCpu,
  FirstIntel,
  IntelMerom = FirstIntel,
  IntelPenryn,
  IntelNehalem,
  IntelWestmere,
  IntelSandyBridge,
  IntelIvyBridge,
  IntelHaswell,
  IntelBroadwell,
  IntelSkylake,
  IntelKabyLake,
  IntelCometLake,
  IntelIceLake,
  IntelTigerLake,
  IntelRocketLake,
  IntelAlderLake,
  IntelRaptorLake,
  IntelSapphireRapids,
  IntelEmeraldRapids,
  IntelGraniteRapids,
  IntelMeteorLake,
  IntelLunarLake,
  IntelArrowLake,
  IntelSilvermont,
  IntelGoldmont,
  IntelTremont,
  IntelGracemont,
  IntelCrestmont,
  IntelSkymont,
  LastIntel = IntelSkymont,
  FirstAMD,
  AMDF15 = FirstAMD,
  AMDZen,
  AMDZen2,
  AMDZen3,
  AMDZen4,
  AMDZen5,
  AMDZen6,
  LastAMD = AMDZen6,
  FirstARM,
  ARMNeoverseN1 = FirstARM,
  ARMNeoverseN2,
  ARMNeoverseN3,
  ARMNeoverseE1,
  ARMNeoverseV1,
  ARMNeoverseV2,
  ARMNeoverseV3AE,
  ARMNeoverseV3,
  ARMCortexA55,
  ARMCortexA75,
  ARMCortexA76,
  ARMCortexA77,
  ARMCortexA78,
  ARMCortexX1,
  ARMCortexA520,
  ARMCortexA720,
  AmpereOne,
  QualcommOryonX1,
  AppleM1Icestorm,
  AppleM1Firestorm,
  AppleM2Blizzard,
  AppleM2Avalanche,
  LastARM = AppleM2Avalanche,
};

struct CPUInfo {
  // The microarch of the CPU core.
  CpuMicroarch microarch;
  // Either PERF_TYPE_RAW or some alternative type that should be used
  // instead of PERF_TYPE_RAW for raw events on this core.
  int raw_perf_event_type;
};

/*
 * Set if this CPU supports ticks counting retired conditional branches.
 */
#define PMU_TICKS_RCB (1<<0)

/*
 * Some CPUs turn off the whole PMU when there are no remaining events
 * scheduled (perhaps as a power consumption optimization). This can be a
 * very expensive operation, and is thus best avoided. For cpus, where this
 * is a problem, we keep a cycles counter (which corresponds to one of the
 * fixed function counters, so we don't use up a programmable PMC) that we
 * don't otherwise use, but keeps the PMU active, greatly increasing
 * performance.
 */
#define PMU_BENEFITS_FROM_USELESS_COUNTER (1<<1)

/*
 * Set if this CPU supports ticks counting all taken branches
 * (excluding interrupts, far branches, and rets).
 */
#define PMU_TICKS_TAKEN_BRANCHES (1<<3)

/*
 * Set if this CPU is known to have essentially unbounded skid,
 * i.e. the provided skid value is exceeded in rare cases.
 */
#define PMU_SKID_UNBOUNDED (1<<4)

struct PmuConfig {
  CpuMicroarch uarch;
  const char* name;
  uint64_t rcb_cntr_event;
  uint64_t minus_ticks_cntr_event;
  uint64_t llsc_cntr_event;
  uint32_t skid_size;
  uint32_t flags;
  const char* pmu_name = nullptr; // ARM only
  uint64_t cycle_event = PERF_COUNT_HW_CPU_CYCLES;
  int cycle_type = PERF_TYPE_HARDWARE;
  int event_type = PERF_TYPE_RAW;
};

// XXX please only edit this if you really know what you're doing.
// event = 0x5101c4:
// - 51 = generic PMU
// - 01 = umask for event BR_INST_RETIRED.CONDITIONAL
// - c4 = eventsel for event BR_INST_RETIRED.CONDITIONAL
// event = 0x5301cb:
// - 51 = generic PMU
// - 01 = umask for event HW_INTERRUPTS.RECEIVED
// - cb = eventsel for event HW_INTERRUPTS.RECEIVED
// See Intel 64 and IA32 Architectures Performance Monitoring Events.
// See check_events from libpfm4.
// Match order of CpuMicroarch.
// For the Intel Core lineage, we use the name of the product rather than
// the official name of the microarchitecture. For hybrid products the
// data in this table is for the P-cores of that product. For E-cores
// we use their actual Atom ("mont") microarchitecture.
static const PmuConfig pmu_configs[] = {
  { UnknownCpu, "Unknown", 0, 0, 0, 0, 0 },
  { IntelMerom, "Intel Merom", 0, 0, 0, 100, 0 },
  { IntelPenryn, "Intel Penryn", 0, 0, 0, 100, 0 },
  { IntelNehalem, "Intel Nehalem", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelWestmere, "Intel Westmere", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelSandyBridge, "Intel Sandy Bridge", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelIvyBridge, "Intel Ivy Bridge", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelHaswell, "Intel Haswell", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelBroadwell, "Intel Broadwell", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelSkylake, "Intel Skylake", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelKabyLake, "Intel Kaby Lake", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelCometLake, "Intel Comet Lake", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelIceLake, "Intel Ice Lake", 0x5111c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelTigerLake, "Intel Tiger Lake", 0x5111c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelRocketLake, "Intel Rocket Lake", 0x5111c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelAlderLake, "Intel Alder Lake", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelRaptorLake, "Intel Raptor Lake", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelSapphireRapids, "Intel Sapphire Rapids", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelEmeraldRapids, "Intel Emerald Rapids", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelGraniteRapids, "Intel Granite Rapids", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelMeteorLake, "Intel Meteor Lake", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelLunarLake, "Intel Lunar Lake", 0x100005111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelArrowLake, "Intel Arrow Lake", 0x100005111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelSilvermont, "Intel Silvermont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelGoldmont, "Intel Goldmont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelTremont, "Intel Tremont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelGracemont, "Intel Gracemont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelCrestmont, "Intel Crestmont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelSkymont, "Intel Skymont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { AMDF15, "AMD Family 15h", 0xc4, 0xc6, 0, 250, PMU_TICKS_TAKEN_BRANCHES },
  // 0xd1 == RETIRED_CONDITIONAL_BRANCH_INSTRUCTIONS - Number of retired conditional branch instructions
  // 0x2c == INTERRUPT_TAKEN - Counts the number of interrupts taken
  // Both counters are available on all Zen microarchitecures so far.
  { AMDZen, "AMD Zen", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  { AMDZen2, "AMD Zen 2", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  { AMDZen3, "AMD Zen 3", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  { AMDZen4, "AMD Zen 4", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  { AMDZen5, "AMD Zen 5", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  // UNTESTED
  { AMDZen6, "AMD Zen 6", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  // Performance cores from ARM from cortex-a76 on (including neoverse-n1 and later)
  // have the following counters that are reliable enough for us.
  // 0x21 == BR_RETIRED - Architecturally retired taken branches
  // 0x6F == STREX_SPEC - Speculatively executed strex instructions
  // 0x11 == CPU_CYCLES - Cycle
  { ARMNeoverseN1, "ARM Neoverse N1", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMNeoverseN2, "ARM Neoverse N2", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMNeoverseN3, "ARM Neoverse N3", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMNeoverseE1, "ARM Neoverse E1", 0, 0, 0, 0, 0 },
  { ARMNeoverseV1, "ARM Neoverse V1", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMNeoverseV2, "ARM Neoverse V2", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMNeoverseV3AE, "ARM Neoverse V3AE", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMNeoverseV3, "ARM Neoverse V3", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  // cortex-a55, cortex-a75 and neoverse-e1 counts uarch ISB
  // as retired branches so the BR_RETIRED counter is not reliable.
  // There are some counters that are somewhat more reliable than
  // the total branch count (0x21) including
  // 0x0D (BR_IMMED_RETIRED) 0x0E (BR_RETURN_RETIRED)
  // 0xCD (BR_INDIRECT_ADDR_PRED) 0x76 (PC_WRITE_SPEC)
  // 0x78 (BR_IMMED_SPEC), 0xC9 (BR_COND_PRED)
  // 0xCD (BR_INDIRECT_ADDR_PRED)
  // but according to tests on the LITTLE core on a snapdragon 865
  // none of them (including the sums) seems to be useful/reliable enough.
  { ARMCortexA55, "ARM Cortex A55", 0, 0, 0, 0, 0 },
  { ARMCortexA75, "ARM Cortex A75", 0, 0, 0, 0, 0 },
  { ARMCortexA76, "ARM Cortex A76", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
  { ARMCortexA77, "ARM Cortex A77", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
  { ARMCortexA78, "ARM Cortex A78", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
  { ARMCortexX1, "ARM Cortex X1", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
  { ARMCortexA520, "ARM Cortex A520", 0, 0, 0, 0, 0 },
  { ARMCortexA720, "ARM Cortex A720", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { AmpereOne, "AmpereOne", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { QualcommOryonX1, "Qualcomm Oryon X1", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
  { AppleM1Icestorm, "Apple M1 Icestorm", 0x90, 0, 0, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "apple_icestorm_pmu", 0x8c, -1, -1 },
  { AppleM1Firestorm, "Apple M1 Firestorm", 0x90, 0, 0, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "apple_firestorm_pmu", 0x8c, -1, -1 },
  { AppleM2Blizzard, "Apple M2 Blizzard", 0x90, 0, 0, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "apple_blizzard_pmu", 0x8c, -1, -1 },
  { AppleM2Avalanche, "Apple M2 Avalanche", 0x90, 0, 0, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "apple_avalanche_pmu", 0x8c, -1, -1 },
};

/* ==== End copying from PerfCounters.cc ==== */

/* ==== Copied from util.h ==== */

typedef struct {
  uint32_t eax, ebx, ecx, edx;
} CPUIDData;

typedef enum  {
  CPUID_GETVENDORSTRING,
  CPUID_GETFEATURES,
  CPUID_GETTLB,
  CPUID_GETSERIAL,
  CPUID_GETCACHEPARAMS = 0x04,
  CPUID_GETEXTENDEDFEATURES = 0x07,
  CPUID_GETEXTENDEDTOPOLOGY = 0x0B,
  CPUID_GETXSAVE = 0x0D,
  CPUID_GETRDTMONITORING = 0x0F,
  CPUID_GETRDTALLOCATION = 0x10,
  CPUID_GETSGX = 0x12,
  CPUID_GETPT = 0x14,
  CPUID_GETSOC = 0x17,
  CPUID_HYPERVISOR = 0x40000000,
  CPUID_INTELEXTENDED = 0x80000000,
  CPUID_INTELFEATURES,
  CPUID_INTELBRANDSTRING,
  CPUID_INTELBRANDSTRINGMORE,
  CPUID_INTELBRANDSTRINGEND,
  CPUID_AMD_CACHE_TOPOLOGY = 0x8000001D,
  CPUID_AMD_PLATFORM_QOS = 0x80000020
} cpuid_requests;

/* ==== End copying from util.h ==== */

/* ==== Copied from CPUs.cc ==== */

struct CPUGroup {
  int start_cpu;
  int end_cpu;
  std::string name;
  int type;
};

static bool read_trimmed_file(const std::filesystem::path& path, std::string* out) {
  std::ifstream file(path);
  if (!file.good()) {
    return false;
  }
  std::ostringstream sstr;
  sstr << file.rdbuf();
  *out = sstr.str();
  while (!out->empty() && (*out)[out->size() - 1] == '\n') {
    out->resize(out->size() - 1);
  }
  return true;
}

static bool hybrid_cpu_arch_parse_cpus(const std::filesystem::path& dir,
                                       CPUGroup* group) {
  std::string s;
  if (!read_trimmed_file(dir / "cpus", &s) || s.empty()) {
    return false;
  }
  size_t dash = s.find('-');
  size_t end;
  if (dash == std::string::npos) {
    group->start_cpu = std::stoi(s, &end);
    group->end_cpu = group->start_cpu + 1;
    return end == s.size();
  }
  group->start_cpu = std::stoi(s.substr(0, dash), &end);
  if (end != dash) {
    return false;
  }
  group->end_cpu = std::stoi(s.substr(dash + 1), &end) + 1;
  return end == s.size() - (dash + 1);
}

static bool hybrid_cpu_arch_parse_type(const std::filesystem::path& dir,
                                       CPUGroup* group) {
  // See https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/intel-hybrid.txt
  std::string s;
  if (!read_trimmed_file(dir / "type", &s)) {
    return false;
  }
  size_t end;
  group->type = std::stoi(s, &end);
  return end == s.size();
}

// Returns an empty list on many (all?) systems that aren't using hybrid cores.
// In that case, assume all CPUs have the same microarch.
__attribute__((unused))
static std::vector<CPUGroup> hybrid_cpu_arch_groups() {
  std::vector<CPUGroup> result;
  std::filesystem::path dir_path = "/sys/devices";
  if (!std::filesystem::is_directory(dir_path)) {
    return result;
  }
  for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
    auto file_name = entry.path().filename().string();
    if (file_name.find("cpu_") != 0) {
      continue;
    }
    CPUGroup group;
    group.name = file_name.substr(4);
    if (!hybrid_cpu_arch_parse_cpus(entry.path(), &group) ||
        !hybrid_cpu_arch_parse_type(entry.path(), &group)) {
      continue;
    }
    result.push_back(std::move(group));
  }
  return result;
}

static cpu_set_t initial_affinity_mask;

static std::vector<int> initial_affinity() {
  std::vector<int> result;
  for (int i = 0; i < CPU_SETSIZE; ++i) {
    if (CPU_ISSET(i, &initial_affinity_mask)) {
      result.push_back(i);
    }
  }
  return result;
}

static bool set_affinity_to_cpu(int cpu) {
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(cpu, &mask);
  return 0 == sched_setaffinity(0, sizeof(mask), &mask);
}

__attribute__((unused))
static void restore_initial_affinity() {
  CHECK(0 == sched_setaffinity(0, sizeof(initial_affinity_mask), &initial_affinity_mask));
}

/* ==== End copying from CPUs.cc ==== */

#if defined(__i386__) || defined(__x86_64__)
/* ==== Copied from util.cc ==== */

CPUIDData cpuid(uint32_t code, uint32_t subrequest) {
  CPUIDData result;
  asm volatile("cpuid"
               : "=a"(result.eax), "=b"(result.ebx), "=c"(result.ecx),
                 "=d"(result.edx)
               : "a"(code), "c"(subrequest));
  return result;
}

/* ==== End copying from util.cc === */

/* ==== Copied from PerfCounters_x86.h ==== */

struct AMDZenModels {
  unsigned int family;
  unsigned int first_model;
  unsigned int last_model;
  CpuMicroarch uarch;
};

// Zen generations by family and model range, matching bsp_init_amd() in
// Linux arch/x86/kernel/cpu/amd.c (as of 87db7795cbaa).
static const AMDZenModels amd_zen_models[] = {
  // Includes Naples, Whitehaven, Summit Ridge, Snowy Owl, Raven Ridge,
  // Great Horned Owl, Banded Kestrel, Dali (Zen), Colfax, Pinnacle Ridge,
  // Picasso (Zen+)
  { 0x17, 0x00, 0x2f, AMDZen },
  { 0x17, 0x50, 0x5f, AMDZen },
  // Includes Rome, Castle Peak, Renoir, Lucienne, Matisse, Van Gogh
  { 0x17, 0x30, 0x4f, AMDZen2 },
  { 0x17, 0x60, 0x7f, AMDZen2 },
  { 0x17, 0x90, 0x91, AMDZen2 },
  { 0x17, 0xa0, 0xaf, AMDZen2 },
  // Includes Milan, Chagall, Vermeer, Cezanne, Rembrandt (Zen 3+)
  { 0x19, 0x00, 0x0f, AMDZen3 },
  { 0x19, 0x20, 0x5f, AMDZen3 },
  // Includes Raphael, Phoenix, Hawk Point, 7975WX
  { 0x19, 0x10, 0x1f, AMDZen4 },
  { 0x19, 0x60, 0xaf, AMDZen4 },
  // Includes Turin, Strix Point, Strix Halo, Krackan Point
  { 0x1a, 0x00, 0x2f, AMDZen5 },
  { 0x1a, 0x40, 0x4f, AMDZen5 },
  { 0x1a, 0x60, 0x7f, AMDZen5 },
  { 0x1a, 0xd0, 0xd7, AMDZen5 },
  // UNTESTED
  { 0x1a, 0x50, 0x5f, AMDZen6 },
  { 0x1a, 0x80, 0xaf, AMDZen6 },
  { 0x1a, 0xc0, 0xcf, AMDZen6 },
  { 0x1a, 0xd8, 0xef, AMDZen6 },
};

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 *
 * Another way to do this would be to read the pmu type under
 * /sys/devices/.../caps/pmu_name. There are tradeoffs:
 *   * With the current approach, rr works with old kernels that haven't
 * been updated with specific knowledge of the CPU type. Reading
 * `pmu_name`, rr would not work.
 *   * Reading `pmu_name`, rr would work with new CPUs that use an
 * existing PMU type, if the kernel is new enough to know about those
 * CPUs. With the current approach users have to have an rr that has
 * been updated for those CPUs.
 * Assuming that it's easier to update rr than update one's kernel,
 * the current approach seems a little better.
 *
 * This detects the overall microarchitecture, which we also use
 * as the microarchitecture identifier for the P-cores of that architecture
 * in a hybrid setup.
 */
static CpuMicroarch compute_cpu_microarch() {
  auto cpuid_vendor = cpuid(CPUID_GETVENDORSTRING, 0);
  char vendor[12];
  memcpy(&vendor[0], &cpuid_vendor.ebx, 4);
  memcpy(&vendor[4], &cpuid_vendor.edx, 4);
  memcpy(&vendor[8], &cpuid_vendor.ecx, 4);
  if (strncmp(vendor, "GenuineIntel", sizeof(vendor)) &&
      strncmp(vendor, "AuthenticAMD", sizeof(vendor))) {
    die("Unknown CPU vendor '%.12s'", vendor);
  }

  auto cpuid_data = cpuid(CPUID_GETFEATURES, 0);
  // Compute the family and model as described in the CPUID documentation
  // from Intel and AMD.
  unsigned int base_family = (cpuid_data.eax >> 8) & 0xf;
  unsigned int family = base_family;
  if (base_family == 0xf) {
    family += (cpuid_data.eax >> 20) & 0xff;
  }
  unsigned int model = (cpuid_data.eax >> 4) & 0xf;
  if (base_family == 0x6 || base_family == 0xf) {
    model |= ((cpuid_data.eax >> 16) & 0xf) << 4;
  }
  switch ((family << 8) | model) {
    case 0x60f:
    case 0x616:
      return IntelMerom;
    case 0x617:
    case 0x61d:
      return IntelPenryn;
    case 0x61a:
    case 0x61e:
    case 0x62e:
      return IntelNehalem;
    case 0x625:
    case 0x62c:
    case 0x62f:
      return IntelWestmere;
    case 0x62a:
    case 0x62d:
    case 0x63e:
      return IntelSandyBridge;
    case 0x63a:
      return IntelIvyBridge;
    case 0x63c: /* Devil's Canyon */
    case 0x63f:
    case 0x645:
    case 0x646:
      return IntelHaswell;
    case 0x63d:
    case 0x647:
    case 0x64f:
    case 0x656:
      return IntelBroadwell;
    case 0x64e:
    case 0x655:
    case 0x65e:
      return IntelSkylake;
    case 0x637:
    case 0x64c:
    case 0x657:
      return IntelSilvermont;
    case 0x65f:
    case 0x67a:
    case 0x65c:
      return IntelGoldmont;
    case 0x69c:
      return IntelTremont;
    case 0x67e:
    case 0x66a:
    case 0x686:
      return IntelIceLake;
    case 0x68c:
    case 0x68d:
      return IntelTigerLake;
    case 0x68e:
    case 0x69e:
      return IntelKabyLake;
    case 0x6a5:
    case 0x6a6:
      return IntelCometLake;
    case 0x6a7:
      return IntelRocketLake;
    case 0x697:
    case 0x69a:
      return IntelAlderLake;
    case 0x6b7:
    case 0x6ba:
    case 0x6bf:
      return IntelRaptorLake;
    case 0x68f:
      return IntelSapphireRapids;
    case 0x6cf:
      return IntelEmeraldRapids;
    case 0x6ad:
      return IntelGraniteRapids;
    case 0x6aa:
      return IntelMeteorLake;
    case 0x6bd:
      return IntelLunarLake;
    case 0x6be:
      return IntelGracemont;
    case 0x6b5:
    case 0x6c5:
    case 0x6c6:
      return IntelArrowLake;
    case 0x1201: // A8-3530MX
    case 0x1502: // Piledriver
    case 0x1530: // Steamroller
      return AMDF15;
    default:
      break;
  }

  if (!strncmp(vendor, "AuthenticAMD", sizeof(vendor))) {
    for (const auto& zen : amd_zen_models) {
      if (family == zen.family && zen.first_model <= model &&
          model <= zen.last_model) {
        return zen.uarch;
      }
    }
    die("AMD CPU family 0x%x model 0x%x unknown", family, model);
  } else {
    die("Intel CPU family 0x%x model 0x%x unknown", family, model);
  }
  return UnknownCpu; // not reached
}

static std::vector<CPUInfo> compute_cpus_info() {
  std::vector<CPUInfo> result;
  auto groups = hybrid_cpu_arch_groups();
  if (groups.empty()) {
    // Only one kind of CPU core.
    result.push_back({compute_cpu_microarch(), PERF_TYPE_RAW});
    return result;
  }

  for (int cpu : initial_affinity()) {
    if (cpu < static_cast<int>(result.size()) &&
        result[cpu].microarch != UnknownCpu) {
      // This cpu belongs to a group we already computed the microarch for.
      // Using groups like this lets us avoid having to schedule this thread
      // on every single CPU in the system.
      continue;
    }
    while (static_cast<int>(result.size()) < cpu) {
      result.push_back({UnknownCpu, PERF_TYPE_RAW});
    }
    if (!set_affinity_to_cpu(cpu)) {
      die("Can't set affinity to previously allowed CPU");
    }
    CpuMicroarch uarch = compute_cpu_microarch();
    // May be overwritten below if this is part of a known hybrid core grouping.
    result.push_back({uarch, PERF_TYPE_RAW});
    // Fill in `result` for all CPUs in the same group as the current CPU.
    // This avoids having to schedule this thread on every single CPU in the
    // system.
    for (auto group : groups) {
      if (group.start_cpu <= cpu && cpu < group.end_cpu) {
        result.resize(group.end_cpu);
        if (group.name == "atom") {
          switch (uarch) {
          case IntelAlderLake:
          case IntelRaptorLake:
            uarch = IntelGracemont;
            break;
          case IntelMeteorLake:
            uarch = IntelCrestmont;
            break;
          case IntelLunarLake:
          case IntelArrowLake:
            // Some Arrow Lakes use Crestmont E-cores maybe? Hopefully doesn't matter
            // for the PMU.
            uarch = IntelSkymont;
            break;
          default:
            die("Atom architecture detected but not known for %d", uarch);
          }
        } else if (group.name == "lowpower") {
          switch (uarch) {
          case IntelArrowLake:
            uarch = IntelCrestmont;
            break;
          default:
            die("Lowpower architecture detected but not known for %d", uarch);
          }
        } else if (group.name != "core") {
          die("Hybrid architecture group name not known: %s", group.name.c_str());
        }
        for (int i = group.start_cpu; i < group.end_cpu; ++i) {
          result[i] = {uarch, group.type};
        }
        break;
      }
    }
  }
  restore_initial_affinity();
  return result;
}

/* ==== End copying from PerfCounters_x86.h ==== */
#endif

#if defined(__aarch64__)
/* ==== End copying from PerfCounters_aarch64.h ==== */

struct CPUID {
  uint8_t implementer = 0;
  uint8_t variant = 0;
  uint16_t part = 0;
  operator bool() const
  {
    return implementer || variant || part;
  }
  // bool operator==(const CPUID&) const = default; // c++20
  bool operator==(const CPUID &other) const
  {
    return implementer == other.implementer &&
      variant == other.variant && part == other.part;
  }
  bool operator!=(const CPUID &other) const
  {
    return !(*this == other);
  }
};

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 */
static CpuMicroarch compute_cpu_microarch(const CPUID &cpuid) {
  switch (cpuid.implementer) {
  case 0x41: // ARM
    switch (cpuid.part) {
    case 0xd05:
      return ARMCortexA55;
    case 0xd0a:
      return ARMCortexA75;
    case 0xd0b:
      return ARMCortexA76;
    case 0xd0d:
      return ARMCortexA77;
    case 0xd41:
    case 0xd4b: // ARM Cortex A78C
      return ARMCortexA78;
    case 0xd44:
    case 0xd4c: // ARM Cortex X1C
      return ARMCortexX1;
    case 0xd80:
      return ARMCortexA520;
    case 0xd81:
      return ARMCortexA720;
    case 0xd0c:
      return ARMNeoverseN1;
    case 0xd49:
      return ARMNeoverseN2;
    case 0xd8e:
      return ARMNeoverseN3;
    case 0xd4a:
      return ARMNeoverseE1;
    case 0xd40:
      return ARMNeoverseV1;
    case 0xd4f:
      return ARMNeoverseV2;
    case 0xd83:
      return ARMNeoverseV3AE;
    case 0xd84:
      return ARMNeoverseV3;
    }
    break;
  case 0x51: // Qualcomm
    switch (cpuid.part) {
    case 0x802:
      return ARMCortexA75;
    case 0x803:
      return ARMCortexA55;
    case 0x804:
      return ARMCortexA76;
    case 0x805:
      return ARMCortexA55;
    case 0x001:
      return QualcommOryonX1;
    }
    break;
  case 0x61: // Apple
    switch (cpuid.part) {
    case 0x22:
    case 0x24:
    case 0x28:
      return AppleM1Icestorm;
    case 0x23:
    case 0x25:
    case 0x29:
      return AppleM1Firestorm;
    case 0x32:
    case 0x34:
    case 0x38:
      return AppleM2Blizzard;
    case 0x33:
    case 0x35:
    case 0x39:
      return AppleM2Avalanche;
    }
    break;
  case 0xc0: // Ampere
    switch (cpuid.part) {
    case 0xac3:
      return AmpereOne;
    }
    break;
  }
  die("Unknown aarch64 CPU type: implementer 0x%x, variant 0x%x, part 0x%x",
      cpuid.implementer, cpuid.variant, cpuid.part);
  return UnknownCpu; // not reached
}

static void set_cpuid(std::vector<CPUID> &cpuids, unsigned long cpuidx, CPUID cpuid)
{
  if (cpuids.size() <= cpuidx) {
    cpuids.resize(cpuidx + 1);
  }
  if (cpuids[cpuidx]) {
    die("Duplicated CPUID for core");
  }
  cpuids[cpuidx] = cpuid;
}

/**
 * The new interface to get ID register values on AArch64
 * `/sys/devices/system/cpu/cpu([0-9]+)/regs/identification/midr_el1`
 * The register value is stored in hex.
 */
static inline void get_cpuinfo_sysfs(std::vector<CPUID> &res)
{
  const std::string cpu_dir = "/sys/devices/system/cpu/";
  const std::regex cpuname_regex("cpu([0-9]+)");
  auto dir = opendir(cpu_dir.c_str());
  if (!dir) {
    return;
  }
  while (auto entry = readdir(dir)) {
    std::cmatch match;
    if (entry->d_type != DT_DIR ||
        !std::regex_match(entry->d_name, match, cpuname_regex)) {
      continue;
    }
    auto cpuidx = std::stoul(match[1].str());
    std::string name = cpu_dir + entry->d_name + "/regs/identification/midr_el1";
    std::ifstream file(name);
    if (!file) {
      die("Failed to read midr register from kernel");
    }
    uint64_t val = 0;
    file >> std::hex >> val;
    if (!file) {
      die("Failed to read midr register from kernel");
    }
    set_cpuid(res, cpuidx, {
        uint8_t(val >> 24),
        uint8_t((val >> 20) & 0xf),
        uint16_t((val >> 4) & 0xfff)
      });
  }
  closedir(dir);
}

/**
 * A line we care about in /proc/cpuinfo starts with a prefix followed by
 * `:` and some white space characters, then followed by the value we care about.
 * Return true if we've found the prefix. Set `flag` to `false`
 * if the value parsing failed.
 *
 * Use an external template since lambda's can't be templated in C++11
 */
template<typename T, typename F>
static inline bool try_read_procfs_line(const std::string &line,
                                        const char *prefix, T &out,
                                        bool &flag, F &&reset)
{
  size_t prefix_len = strlen(prefix);
  if (line.size() < prefix_len) {
    return false;
  }
  if (memcmp(&line[0], prefix, prefix_len) != 0) {
    return false;
  }
  if (flag) {
    // We've seen this already,
    // i.e. we didn't see a new line between the processor lines
    reset();
  }
  const char *p = &line[prefix_len];
  // Skip blank and `:`.
  while (*p == '\t' || *p == ' ' || *p == ':') {
    p++;
  }
  char *str_end;
  auto num = std::strtoull(p, &str_end, 0);
  out = (T)num;
  if (str_end == p) {
    flag = false;
  } else if (num > (unsigned long long)std::numeric_limits<T>::max()) {
    flag = false;
  } else {
    flag = true;
  }
  return true;
}

/**
 * /proc/cpuinfo reader
 * The cpuinfo file contains blocks of text for each core.
 * The blocks are separated by empty lines and it should start with a
 * `processor : <num>` line followed by lines showing properties of the core.
 * The three property lines we are looking for starts with
 * `CPU implementer`, `CPU variant` and `CPU part`.
 */
static inline void get_cpuinfo_procfs(std::vector<CPUID> &res)
{
  std::ifstream file("/proc/cpuinfo");
  CPUID cpuid = {0, 0, 0};
  unsigned cpuidx = 0;
  bool has_cpuidx = false;
  bool has_impl = false;
  bool has_part = false;
  bool has_var = false;
  auto reset = [&] () {
    // Few (none) of the detection code care about the variant number
    // so we'll accept it if we couldn't read it.
    if (has_cpuidx && has_impl && has_part) {
      set_cpuid(res, cpuidx, cpuid);
    }
    has_cpuidx = false;
    has_impl = false;
    has_part = false;
    has_var = false;
    cpuid = {0, 0, 0};
  };
  for (std::string line; std::getline(file, line);) {
    // Empty lines means that we've finished processing of a block
    if (line.empty()) {
      reset();
      continue;
    }
    // First find the processor line
    if (try_read_procfs_line(line, "processor", cpuidx, has_cpuidx, reset)) {
      continue;
    }
    // and ignore the line until we found the processor line.
    if (!has_cpuidx) {
      continue;
    }

    // Try parsing as one of the data lines.
    // Short circuiting after the first hit.
    try_read_procfs_line(line, "CPU implementer", cpuid.implementer, has_impl, reset) ||
      try_read_procfs_line(line, "CPU variant", cpuid.variant, has_var, reset) ||
      try_read_procfs_line(line, "CPU part", cpuid.part, has_part, reset);
  }
  reset();
}

static std::vector<CPUInfo> compute_cpus_info() {
  std::vector<CPUInfo> result;
  std::vector<CPUID> cpuids;
  get_cpuinfo_sysfs(cpuids);
  if (cpuids.empty()) {
    fprintf(stderr, "Unable to read CPU type from sysfs, trying procfs instead.\n");
    get_cpuinfo_procfs(cpuids);
  }
  if (cpuids.empty()) {
    die("Failed to read midr register from kernel");
  }
  for (auto &cpuid : cpuids) {
    if (!cpuid) {
      die("Unable to find CPU id for core %d", (int)(&cpuid - &cpuids[0]));
    }
  }
  auto cpuid0 = cpuids[0];
  bool single_uarch = true;
  for (auto &cpuid : cpuids) {
    if (cpuid != cpuid0) {
      single_uarch = false;
      break;
    }
  }
  if (single_uarch) {
    result.push_back({compute_cpu_microarch(cpuid0), PERF_TYPE_RAW});
    return result;
  }
  for (auto &cpuid : cpuids) {
    result.push_back({compute_cpu_microarch(cpuid), PERF_TYPE_RAW});
  }
  return result;
}

/* ==== End copying from PerfCounters_aarch64.h ==== */
#endif

static int parent_to_child_fds[2];
static int child_to_parent_fds[2];
static char do_test_ticks_basic;
static char do_test_ticks_syscalls;

/* Tell the parent we're ready, then wait for the parent to signal us,
   without executing any conditional branches.
   Note: this must be compiled with -fno-stack-protector or we'll get a conditional
   branch in here.
 */
static void child_wait(void) {
#if defined(__x86_64__)
  /* write(child_to_parent_fds[1], buf, 1) */
  /* Use hand-rolled syscalls to avoid conditional branches (e.g. setting errno) */
  __asm__ __volatile__ ("syscall" : : "a"(__NR_write), "D"(child_to_parent_fds[1]), "S"("x"), "d"(1) : "rcx", "r11", "flags");
  char buf;
  /* read(parent_to_child_fds[0], buf, 1) */
  __asm__ __volatile__ ("syscall" : : "a"(__NR_read), "D"(parent_to_child_fds[0]), "S"(&buf), "d"(1) : "rcx", "r11", "flags");
#elif defined(__i386__)
  /* write(child_to_parent_fds[1], buf, 1) */
  /* Use hand-rolled syscalls to avoid conditional branches (e.g. setting errno) */
  __asm__ __volatile__ ("int $0x80" : : "a"(__NR_write), "b"(child_to_parent_fds[1]), "c"("x"), "d"(1));
  char buf;
  /* read(parent_to_child_fds[0], buf, 1) */
  __asm__ __volatile__ ("int $0x80" : : "a"(__NR_read), "b"(parent_to_child_fds[0]), "c"(&buf), "d"(1));
#elif defined(__aarch64__)
  /* write(child_to_parent_fds[1], buf, 1) */
  register long x8 __asm__("x8") = __NR_write;
  register long x0 __asm__("x0") = child_to_parent_fds[1];
  register long x1 __asm__("x1") = (long)"x";
  register long x2 __asm__("x2") = (long)1;
  /* Use hand-rolled syscalls to avoid conditional branches (e.g. setting errno) */
  __asm__ volatile("svc #0\n\t"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x8));
  char buf;
  x8 = __NR_read;
  x0 = parent_to_child_fds[0];
  x1 = (long)&buf;
  x2 = (long)1;
  /* read(parent_to_child_fds[0], buf, 1) */
  __asm__ volatile("svc #0\n\t"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x8));
#endif
}

#define NUM_ITERATIONS_BASIC 100000
#define NUM_VOLATILE_UPDATES 1000
#define NUM_ITERATIONS_SYSCALLS 100000

static volatile long volatile_value;

void test_ticks_basic(void) {
  int i, j;
  for (i = 0; i < NUM_ITERATIONS_BASIC; ++i) {
    child_wait();
    volatile_value = 0;
    for (j = 0; j < NUM_VOLATILE_UPDATES; ++j) {
      ++volatile_value;
    }
  }
  child_wait();
}

void test_ticks_syscalls(void) {
  int i, j;
  char buf[1024];
  for (i = 0; i < NUM_ITERATIONS_SYSCALLS; ++i) {
    child_wait();
    size_t buflen = i % sizeof(buf);
    /* Use hand-rolled syscalls to avoid conditional branches (e.g. setting errno) */
#if defined(__x86_64__)
    __asm__ __volatile__ ("syscall" : : "a"(__NR_getrandom), "D"(buf), "S"(buflen), "d"(0) : "rcx", "r11", "flags");
    __asm__ __volatile__ ("syscall" : : "a"(__NR_sched_yield) : "rcx", "r11", "flags");
#elif defined(__i386__)
    __asm__ __volatile__ ("int $0x80" : : "a"(__NR_getrandom), "b"(buf), "c"(buflen), "d"(0));
    __asm__ __volatile__ ("int $0x80" : : "a"(__NR_sched_yield));
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = __NR_getrandom;
    register long x0 __asm__("x0") = (long)buf;
    register long x1 __asm__("x1") = buflen;
    register long x2 __asm__("x2") = 0;
    __asm__ volatile("svc #0\n\t"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x8));
    x8 = __NR_sched_yield;
    __asm__ volatile("svc #0\n\t"
                     : "+r"(x0)
                     : "r"(x8));
#endif
  }
  child_wait();
}

void sighandler(int sig) {
  child_wait();
}

void test_interrupts(void) {
  /* wait for the parent to set the period */
  child_wait();
  /* Sync with the parent every time we get a signal */
  signal(SIGIO, sighandler);
  volatile_value = 0;
  /* Loop forever. Eventually the parent will kill us. */
  while (!volatile_value) {
  }
}

static int do_child(void) {
  if (do_test_ticks_basic) {
    test_ticks_basic();
  }
  if (do_test_ticks_syscalls) {
    test_ticks_syscalls();
  }
  test_interrupts();
  return 0;
}

typedef uint64_t Ticks;

static void check_ticks(Ticks got, Ticks expected) {
  if (got != expected) {
    fprintf(stderr, "Ticks mismatch; got %lld, expected %lld\n", (long long)got, (long long)expected);
    abort();
  }
}

static void reset_counter_period(int counter_fd, uint64_t period) {
  CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_DISABLE, 0));
  CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_RESET, 0));
  CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_PERIOD, &period));
  CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_ENABLE, 0));
}

/* Wait for child to pause, read counter value, reset the counter value,
   resume the child, and report the read counter value */
static Ticks reset_counting(pid_t child, int counter_fd, uint64_t period) {
  char ch;
  CHECK(1 == read(child_to_parent_fds[0], &ch, 1));
  CHECK(ch == 'x');
  Ticks ticks;
  CHECK(sizeof(ticks) == read(counter_fd, &ticks, sizeof(ticks)));
  reset_counter_period(counter_fd, period);
  CHECK(1 == write(parent_to_child_fds[1], "y", 1));
  return ticks;
}

#define MAX_PERIOD 0x1000000000000000LL

int main(int argc, char** argv) {
  int interrupt_tests = 1;
  int interrupt_period = 1000000;

  if (argc > 1) {
    interrupt_tests = atoi(argv[1]);
  }
  if (argc > 2) {
    interrupt_period = atoi(argv[2]);
  }

  CHECK(0 == sched_getaffinity(0, sizeof(initial_affinity_mask), &initial_affinity_mask));
  std::vector<CPUInfo> cpus_info = compute_cpus_info();
  // Test on the first CPU we're allowed to run on. The child inherits this
  // affinity. With multiple kinds of cores, cpus_info is indexed by CPU.
  int cpu = initial_affinity()[0];
  CHECK(set_affinity_to_cpu(cpu));
  CPUInfo cpu_info = cpus_info.size() == 1 ? cpus_info[0] : cpus_info[cpu];

  const PmuConfig* pmu = NULL;
  for (size_t i = 0; i < sizeof(pmu_configs)/sizeof(pmu_configs[0]); ++i) {
    if (cpu_info.microarch == pmu_configs[i].uarch) {
      pmu = &pmu_configs[i];
      break;
    }
  }
  CHECK(pmu);
  printf("Testing on CPU %d: %s\n", cpu, pmu->name);

  do_test_ticks_basic = (pmu->flags & PMU_TICKS_RCB) != 0;
  do_test_ticks_syscalls = (pmu->flags & PMU_TICKS_RCB) != 0;

  CHECK(0 == pipe(parent_to_child_fds));
  CHECK(0 == pipe(child_to_parent_fds));

  pid_t child = fork();
  if (!child) {
    return do_child();
  }
  CHECK(child >= 0);

  struct perf_event_attr perf_attr;
  memset(&perf_attr, 0, sizeof(perf_attr));
  perf_attr.type = cpu_info.raw_perf_event_type;
  perf_attr.size = sizeof(perf_attr);
  perf_attr.config = pmu->rcb_cntr_event;
  perf_attr.exclude_kernel = 1;
  perf_attr.exclude_guest = 1;
  perf_attr.pinned = 1;
  perf_attr.sample_period = MAX_PERIOD;

  int counter_fd = syscall(__NR_perf_event_open, &perf_attr, child, -1, -1, PERF_FLAG_FD_CLOEXEC);
  CHECK(counter_fd >= 0);

  if (do_test_ticks_basic) {
    reset_counting(child, counter_fd, MAX_PERIOD);
    for (int i = 0; i < NUM_ITERATIONS_BASIC; ++i) {
      Ticks ticks = reset_counting(child, counter_fd, MAX_PERIOD);
      /* NUM_VOLATILE_UPDATES conditional branches for the inner loop, plus one conditional branch
         for the outer loop. */
      int expect;
      if (i == 0) {
        if (ticks == NUM_VOLATILE_UPDATES + 1) {
          expect = ticks;
        } else {
          expect = NUM_VOLATILE_UPDATES + 2;
        }
      } else {
        expect = NUM_VOLATILE_UPDATES + 2;
      }
      check_ticks(ticks, expect);
    }
  }

  if (do_test_ticks_syscalls) {
    reset_counting(child, counter_fd, MAX_PERIOD);
    for (int i = 0; i < NUM_ITERATIONS_SYSCALLS; ++i) {
      Ticks ticks = reset_counting(child, counter_fd, MAX_PERIOD);
      /* One conditional branch for the outer loop. */
      check_ticks(ticks, 1);
    }
  }

  /* program an interrupt */
  CHECK(0 == fcntl(counter_fd, F_SETOWN, child));
  CHECK(0 == fcntl(counter_fd, F_SETFL, O_ASYNC));

  reset_counting(child, counter_fd, interrupt_period);
  for (int i = 0; i < interrupt_tests; ++i) {
    char ch;
    CHECK(1 == read(child_to_parent_fds[0], &ch, 1));
    CHECK(ch == 'x');
    Ticks ticks;
    CHECK(sizeof(ticks) == read(counter_fd, &ticks, sizeof(ticks)));
    printf("Interrupted after %lld ticks, expected %lld ticks\n", (long long)ticks, (long long)interrupt_period);
    CHECK(ticks >= interrupt_period);
    if (ticks > interrupt_period + pmu->skid_size) {
      fprintf(stderr, "Skid %d exceeded :-(\n", pmu->skid_size);
      fflush(stdout);
      abort();
    }
    reset_counter_period(counter_fd, interrupt_period);
    CHECK(1 == write(parent_to_child_fds[1], "y", 1));
  }

  kill(child, SIGKILL);
  int status;
  CHECK(child == waitpid(child, &status, 0));
  CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  puts("EXIT-SUCCESS");

  return 0;
}
