#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <signal.h>
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
#include <fstream>
#include <iostream>
#include <limits>
#include <regex>
#include <vector>

#define CHECK(condition) \
  do { \
    if (!(condition)) { \
      fprintf(stderr, "CHECK '%s' failed at %s:%d (errno=%d)\n", #condition, __FILE__, __LINE__, errno); \
      abort(); \
    } \
  } while (0)

static void die(const char* msg) {
  fprintf(stderr, "%s\n", msg);
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
  IntelSilvermont,
  IntelGoldmont,
  IntelTremont,
  IntelKabylake,
  IntelCometlake,
  IntelIcelake,
  IntelTigerlake,
  IntelRocketlake,
  IntelAlderlake,
  IntelRaptorlake,
  IntelSapphireRapid,
  IntelEmeraldRapid,
  IntelGraniteRapid,
  IntelMeteorLake,
  IntelArrowLake,
  LastIntel = IntelArrowLake,
  FirstAMD,
  AMDF15 = FirstAMD,
  AMDZen,
  LastAMD = AMDZen,
  FirstARM,
  ARMNeoverseN1 = FirstARM,
  ARMNeoverseE1,
  ARMNeoverseV1,
  ARMNeoverseN2,
  ARMCortexA55,
  ARMCortexA75,
  ARMCortexA76,
  ARMCortexA77,
  ARMCortexA78,
  ARMCortexX1,
  AppleM1Icestorm,
  AppleM1Firestorm,
  AppleM2Blizzard,
  AppleM2Avalanche,
  LastARM = AppleM2Avalanche,
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

struct PmuConfig {
  CpuMicroarch uarch;
  const char* name;
  unsigned rcb_cntr_event;
  unsigned minus_ticks_cntr_event;
  unsigned llsc_cntr_event;
  uint32_t skid_size;
  uint32_t flags;
  const char* pmu_name = nullptr; // ARM only
  unsigned cycle_event = PERF_COUNT_HW_CPU_CYCLES;
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
static const PmuConfig pmu_configs[] = {
  { IntelGraniteRapid, "Intel GraniteRapid", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelEmeraldRapid, "Intel EmeraldRapid", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelSapphireRapid, "Intel SapphireRapid", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelArrowLake, "Intel Arrowlake", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelMeteorLake, "Intel Meteorlake", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelRaptorlake, "Intel Raptorlake", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelAlderlake, "Intel Alderlake", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelRocketlake, "Intel Rocketlake", 0x5111c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelTigerlake, "Intel Tigerlake", 0x5111c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelIcelake, "Intel Icelake", 0x5111c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelCometlake, "Intel Cometlake", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelKabylake, "Intel Kabylake", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelSilvermont, "Intel Silvermont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelGoldmont, "Intel Goldmont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelTremont, "Intel Tremont", 0x517ec4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelSkylake, "Intel Skylake", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelBroadwell, "Intel Broadwell", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelHaswell, "Intel Haswell", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelIvyBridge, "Intel Ivy Bridge", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelSandyBridge, "Intel Sandy Bridge", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelNehalem, "Intel Nehalem", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelWestmere, "Intel Westmere", 0x5101c4, 0, 0, 100, PMU_TICKS_RCB },
  { IntelPenryn, "Intel Penryn", 0, 0, 0, 100, 0 },
  { IntelMerom, "Intel Merom", 0, 0, 0, 100, 0 },
  { AMDF15, "AMD Family 15h", 0xc4, 0xc6, 0, 250, PMU_TICKS_TAKEN_BRANCHES },
  // 0xd1 == RETIRED_CONDITIONAL_BRANCH_INSTRUCTIONS - Number of retired conditional branch instructions
  // 0x2c == INTERRUPT_TAKEN - Counts the number of interrupts taken
  // Both counters are available on Zen, Zen+ and Zen2.
  { AMDZen, "AMD Zen", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB },
  // Performance cores from ARM from cortex-a76 on (including neoverse-n1 and later)
  // have the following counters that are reliable enough for us.
  // 0x21 == BR_RETIRED - Architecturally retired taken branches
  // 0x6F == STREX_SPEC - Speculatively executed strex instructions
  // 0x11 == CPU_CYCLES - Cycle
  { ARMNeoverseN1, "ARM Neoverse N1", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMNeoverseV1, "ARM Neoverse V1", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMNeoverseN2, "ARM Neoverse N2", 0x21, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3_0", 0x11, -1, -1 },
  { ARMCortexA76, "ARM Cortex A76", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
  { ARMCortexA77, "ARM Cortex A77", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
  { ARMCortexA78, "ARM Cortex A78", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
  { ARMCortexX1, "ARM Cortex X1", 0x21, 0, 0x6F, 10000, PMU_TICKS_TAKEN_BRANCHES,
    "armv8_pmuv3", 0x11, -1, -1 },
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
  { ARMNeoverseE1, "ARM Neoverse E1", 0, 0, 0, 0, 0 },
  { ARMCortexA55, "ARM Cortex A55", 0, 0, 0, 0, 0 },
  { ARMCortexA75, "ARM Cortex A75", 0, 0, 0, 0, 0 },
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

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 */
static CpuMicroarch compute_cpu_microarch(void) {
  CPUIDData cpuid_vendor = cpuid(CPUID_GETVENDORSTRING, 0);
  char vendor[12];
  memcpy(&vendor[0], &cpuid_vendor.ebx, 4);
  memcpy(&vendor[4], &cpuid_vendor.edx, 4);
  memcpy(&vendor[8], &cpuid_vendor.ecx, 4);
  if (strncmp(vendor, "GenuineIntel", sizeof(vendor)) &&
      strncmp(vendor, "AuthenticAMD", sizeof(vendor))) {
    die("Unknown CPU vendor");
  }

  CPUIDData cpuid_data = cpuid(CPUID_GETFEATURES, 0);
  unsigned int cpu_type = cpuid_data.eax & 0xF0FF0;
  unsigned int ext_family = (cpuid_data.eax >> 20) & 0xff;
  switch (cpu_type) {
    case 0x006F0:
    case 0x10660:
      return IntelMerom;
    case 0x10670:
    case 0x106D0:
      return IntelPenryn;
    case 0x106A0:
    case 0x106E0:
    case 0x206E0:
      return IntelNehalem;
    case 0x20650:
    case 0x206C0:
    case 0x206F0:
      return IntelWestmere;
    case 0x206A0:
    case 0x206D0:
    case 0x306e0:
      return IntelSandyBridge;
    case 0x306A0:
      return IntelIvyBridge;
    case 0x306C0: /* Devil's Canyon */
    case 0x306F0:
    case 0x40650:
    case 0x40660:
      return IntelHaswell;
    case 0x306D0:
    case 0x40670:
    case 0x406F0:
    case 0x50660:
      return IntelBroadwell;
    case 0x406e0:
    case 0x50650:
    case 0x506e0:
      return IntelSkylake;
    case 0x30670:
    case 0x406c0:
    case 0x50670:
      return IntelSilvermont;
    case 0x506f0:
    case 0x706a0:
    case 0x506c0:
      return IntelGoldmont;
    case 0x706e0:
    case 0x606a0:
      return IntelIcelake;
    case 0x806c0:
    case 0x806d0:
      return IntelTigerlake;
    case 0x806e0:
    case 0x906e0:
      return IntelKabylake;
    case 0xa0650:
    case 0xa0660:
      return IntelCometlake;
    case 0xa0670:
      return IntelRocketlake;
    case 0x90670:
    case 0x906a0:
      return IntelAlderlake;
    case 0xb0670:
      return IntelRaptorlake;
    case 0x806f0:
      return IntelSapphireRapid;
    case 0xc06f0:
      return IntelEmeraldRapid;
    case 0xa06d0:
      return IntelGraniteRapid;
    case 0xa06a0:
      return IntelMeteorLake;
    case 0xc0660:
      return IntelArrowLake;
    case 0xf20:
    case 0x30f00:
      return AMDF15;
    case 0x00f10: // Naples, Whitehaven, Summit Ridge, Snowy Owl (Zen), Milan (Zen 3) (UNTESTED)
    case 0x10f10: // Raven Ridge, Great Horned Owl (Zen) (UNTESTED)
    case 0x10f80: // Banded Kestrel (Zen), Picasso (Zen+) (UNTESTED)
    case 0x20f00: // Dali (Zen) (UNTESTED)
    case 0x00f80: // Colfax, Pinnacle Ridge (Zen+) (UNTESTED)
    case 0x30f10: // Rome, Castle Peak (Zen 2)
    case 0x60f00: // Renoir (Zen 2) (UNTESTED)
    case 0x70f10: // Matisse (Zen 2) (UNTESTED)
    case 0x60f80: // Lucienne
    case 0x90f00: // Van Gogh (Zen 2)
      if (ext_family == 8 || ext_family == 0xa) {
        return AMDZen;
      } else if (ext_family == 3) {
        return AMDF15;
      }
      break;
    case 0x20f10: // Vermeer (Zen 3)
    case 0x50f00: // Cezanne (Zen 3)
    case 0x40f40: // Rembrandt (Zen 3+)
    case 0x60f10: // Raphael (Zen 4)
    case 0x70f40: // Phoenix (Zen 4)
    case 0x70f50: // Hawk Point (Zen 4)
      if (ext_family == 0xa) {
        return AMDZen;
      }
    default:
      break;
  }

  if (!strncmp(vendor, "AuthenticAMD", sizeof(vendor))) {
    die("AMD CPU type unknown");
  } else {
    die("Intel CPU type unknown");
  }
  return UnknownCpu; // not reached
}

static std::vector<CpuMicroarch> compute_cpu_microarchs() {
  return { compute_cpu_microarch() };
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
    case 0xd0c:
      return ARMNeoverseN1;
    case 0xd0d:
      return ARMCortexA77;
    case 0xd40:
      return ARMNeoverseV1;
    case 0xd41:
    case 0xd4b: // ARM Cortex A78C
      return ARMCortexA78;
    case 0xd44:
    case 0xd4c: // ARM Cortex X1C
      return ARMCortexX1;
    case 0xd49:
      return ARMNeoverseN2;
    case 0xd4a:
      return ARMNeoverseE1;
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
      return AppleM2Blizzard;
    case 0x33:
      return AppleM2Avalanche;
    }
    break;
  }
  die("Unknown aarch64 CPU type");
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

static std::vector<CpuMicroarch> compute_cpu_microarchs() {
  std::vector<CPUID> cpuids;
  get_cpuinfo_sysfs(cpuids);
  if (cpuids.empty()) {
    fprintf(stderr, "Unable to read CPU type from sysfs, trying procfs instead.");
    get_cpuinfo_procfs(cpuids);
  }
  if (cpuids.empty()) {
    die("Failed to read midr register from kernel");
  }
  for (auto &cpuid : cpuids) {
    if (!cpuid) {
      die("Unable to find CPU id for core");
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
    return { compute_cpu_microarch(cpuid0) };
  }
  std::vector<CpuMicroarch> uarchs;
  for (auto &cpuid : cpuids) {
    uarchs.push_back(compute_cpu_microarch(cpuid));
  }
  return uarchs;
}

/* ==== End copying from PerfCounters_aarch64.h ==== */
#endif

static int parent_to_child_fds[2];
static int child_to_parent_fds[2];
static char do_test_ticks_basic;
static char do_test_ticks_syscalls;

/* Tell the parent we're ready, then wait for the parent to signal us,
   without executing any conditional branches */
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

  // Assume CPU 0 for now.
  CpuMicroarch uarch = compute_cpu_microarchs()[0];

  const PmuConfig* pmu = NULL;
  for (size_t i = 0; i < sizeof(pmu_configs)/sizeof(pmu_configs[0]); ++i) {
    if (uarch == pmu_configs[i].uarch) {
      pmu = &pmu_configs[i];
      break;
    }
  }
  CHECK(pmu);

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
  perf_attr.type = PERF_TYPE_RAW;
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
