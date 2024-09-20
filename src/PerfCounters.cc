/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "PerfCounters.h"

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#ifdef BPF
#include <bpf/libbpf.h>
#include <linux/hw_breakpoint.h>
#endif

#include <algorithm>
#include <fstream>
#include <limits>
#include <regex>
#include <string>
#include <unordered_set>

#include "Flags.h"
#include "Session.h"
#include "Task.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

#define PERF_COUNT_RR 0x72727272L

static bool attributes_initialized;
// At some point we might support multiple kinds of ticks for the same CPU arch.
// At that point this will need to become more complicated.
struct perf_event_attrs {
  // bug_flags is an architecture dependent flags to determine
  // what bugs need to be checked.
  // Current, this is simply the uarch on x86 and unused on aarch64.
  int bug_flags = 0;
  perf_event_attr ticks{};
  perf_event_attr minus_ticks{};
  perf_event_attr cycles{};
  perf_event_attr llsc_fail{};
  const char *pmu_name = nullptr;
  uint32_t pmu_flags = 0;
  uint32_t skid_size = 0;
  bool checked = false;
  bool has_ioc_period_bug = false;
  bool only_one_counter = false;
  bool activate_useless_counter = false;
};
// If this contains more than one element, it's indexed by the CPU index.
static std::vector<perf_event_attrs> perf_attrs;
static uint32_t pmu_semantics_flags;

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
  IntelMeteorLake,
  LastIntel = IntelMeteorLake,
  FirstAMD,
  AMDF15 = FirstAMD,
  AMDZen,
  AMDZen2,
  AMDZen3,
  AMDZen4,
  LastAMD = AMDZen4,
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

/*
 * Set if this CPU is known to have essentially unbounded skid,
 * i.e. the provided skid value is exceeded in rare cases.
 */
#define PMU_SKID_UNBOUNDED (1<<4)

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
  { IntelEmeraldRapid, "Intel EmeraldRapid", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
  { IntelSapphireRapid, "Intel SapphireRapid", 0x5111c4, 0, 0, 125, PMU_TICKS_RCB },
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
  // Both counters are available on all Zen microarchitecures so far.
  { AMDZen, "AMD Zen", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  { AMDZen2, "AMD Zen 2", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  { AMDZen3, "AMD Zen 3", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
  { AMDZen4, "AMD Zen 4", 0x5100d1, 0, 0, 10000, PMU_TICKS_RCB | PMU_SKID_UNBOUNDED },
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

#define RR_SKID_MAX 10000

static string lowercase(const string& s) {
  string c = s;
  transform(c.begin(), c.end(), c.begin(), ::tolower);
  return c;
}

// The index of the PMU we are using within perf_attrs.
// This is always 0 if we detected a single PMU type
// and will be the same as the CPU index if we detected multiple PMU types.
static int get_pmu_index(int cpu_binding)
{
  if (cpu_binding < 0) {
    if (perf_attrs.size() > 1) {
      CLEAN_FATAL() << "\nMultiple PMU types detected. Unbinding CPU is not supported.";
    }
    return 0;
  }
  if (!PerfCounters::support_cpu(cpu_binding)) {
    CLEAN_FATAL() << "\nPMU on cpu " << cpu_binding << " is not supported.";
  }
  if (perf_attrs.size() == 1) {
    // Single PMU type.
    return 0;
  }
  if ((size_t)cpu_binding > perf_attrs.size()) {
    CLEAN_FATAL() << "\nUnable to find PMU type for CPU " << cpu_binding;
  }
  return cpu_binding;
}

static void init_perf_event_attr(struct perf_event_attr* attr,
                                 unsigned type, unsigned config) {
  memset(attr, 0, sizeof(*attr));
  attr->type = perf_type_id(type);
  attr->size = sizeof(*attr);
  attr->config = config;
  // rr requires that its events count userspace tracee code
  // only.
  attr->exclude_kernel = 1;
  attr->exclude_guest = 1;
}

static const uint64_t IN_TX = 1ULL << 32;
static const uint64_t IN_TXCP = 1ULL << 33;

static int64_t read_counter(ScopedFd& fd) {
  int64_t val;
  ssize_t nread = read(fd, &val, sizeof(val));
  DEBUG_ASSERT(nread == sizeof(val));
  return val;
}

// Can return a closed fd if `tid > 0` and the task was just SIGKILLed.
static ScopedFd start_counter(pid_t tid, int group_fd,
                              struct perf_event_attr* attr,
                              bool* disabled_txcp = nullptr) {
  if (disabled_txcp) {
    *disabled_txcp = false;
  }
  attr->pinned = group_fd == -1;
  int fd = syscall(__NR_perf_event_open, attr, tid, -1, group_fd, PERF_FLAG_FD_CLOEXEC);
  if (fd < 0 && errno == EINVAL && attr->type == PERF_TYPE_RAW &&
      (attr->config & IN_TXCP)) {
    // The kernel might not support IN_TXCP, so try again without it.
    struct perf_event_attr tmp_attr = *attr;
    tmp_attr.config &= ~IN_TXCP;
    fd = syscall(__NR_perf_event_open, &tmp_attr, tid, -1, group_fd, PERF_FLAG_FD_CLOEXEC);
    if (fd >= 0) {
      if (disabled_txcp) {
        *disabled_txcp = true;
      }
      LOG(warn) << "kernel does not support IN_TXCP";
      if ((cpuid(CPUID_GETEXTENDEDFEATURES, 0).ebx & HLE_FEATURE_FLAG) &&
          !Flags::get().suppress_environment_warnings) {
        fprintf(stderr,
                "Your CPU supports Hardware Lock Elision but your kernel does\n"
                "not support setting the IN_TXCP PMU flag. Record and replay\n"
                "of code that uses HLE will fail unless you update your\n"
                "kernel.\n");
      }
    }
  }
  if (fd < 0) {
    switch (errno) {
      case EACCES:
      case EPERM:
        CLEAN_FATAL() << "Permission denied to use 'perf_event_open'; are hardware perf events "
                   "available? See https://github.com/rr-debugger/rr/wiki/Will-rr-work-on-my-system";
        break;
      case ENOENT:
        CLEAN_FATAL() << "Unable to open performance counter with 'perf_event_open'; "
                   "are hardware perf events available? See https://github.com/rr-debugger/rr/wiki/Will-rr-work-on-my-system";
        break;
      case ESRCH:
        if (tid > 0) {
          break;
        }
        RR_FALLTHROUGH;
      default:
        FATAL() << "Failed to initialize counter";
        break;
    }
  }
  return ScopedFd(fd);
}

static void check_for_ioc_period_bug(perf_event_attrs &perf_attr) {
  // Start a cycles counter
  struct perf_event_attr attr = perf_attr.ticks;
  attr.sample_period = 0xffffffff;
  attr.exclude_kernel = 1;
  ScopedFd bug_fd = start_counter(0, -1, &attr);

  uint64_t new_period = 1;
  if (ioctl(bug_fd, PERF_EVENT_IOC_PERIOD, &new_period)) {
    FATAL() << "ioctl(PERF_EVENT_IOC_PERIOD) failed";
  }

  struct pollfd poll_bug_fd = {.fd = bug_fd, .events = POLL_IN, .revents = 0 };
  poll(&poll_bug_fd, 1, 0);

  perf_attr.has_ioc_period_bug = poll_bug_fd.revents == 0;
  LOG(debug) << "has_ioc_period_bug=" << perf_attr.has_ioc_period_bug;
}

static const int NUM_BRANCHES = 500;

volatile uint32_t accumulator_sink = 0;

static void do_branches() {
  // Do NUM_BRANCHES conditional branches that can't be optimized out.
  // 'accumulator' is always odd and can't be zero
  uint32_t accumulator = uint32_t(rand()) * 2 + 1;
  for (int i = 0; i < NUM_BRANCHES && accumulator; ++i) {
    accumulator = ((accumulator * 7) + 2) & 0xffffff;
  }
  // Use 'accumulator' so it can't be  optimized out.
  accumulator_sink = accumulator;
}

// Architecture specific detection code
#if defined(__i386__) || defined(__x86_64__)
#include "PerfCounters_x86.h"
#elif defined(__aarch64__)
#include "PerfCounters_aarch64.h"
#else
#error Must define microarchitecture detection code for this architecture
#endif

static void check_working_counters(perf_event_attrs &perf_attr) {
  struct perf_event_attr attr = perf_attr.ticks;
  attr.sample_period = 0;
  struct perf_event_attr attr2 = perf_attr.cycles;
  attr2.sample_period = 0;
  ScopedFd fd = start_counter(0, -1, &attr);
  ScopedFd fd2 = start_counter(0, -1, &attr2);
  do_branches();
  int64_t events = read_counter(fd);
  int64_t events2 = read_counter(fd2);

  if (events < NUM_BRANCHES) {
    char config[100];
    sprintf(config, "%llx", (long long)perf_attr.ticks.config);
    std::string perf_cmdline = "perf stat -e ";
    if (perf_attr.pmu_name) {
      perf_cmdline = perf_cmdline + perf_attr.pmu_name + "/r" + config + "/ true";
    }
    else {
      perf_cmdline = perf_cmdline + "r" + config + " true";
    }
    FATAL()
        << "\nGot " << events << " branch events, expected at least "
        << NUM_BRANCHES
        << ".\n"
           "\nThe hardware performance counter seems to not be working. Check\n"
           "that hardware performance counters are working by running\n"
           "  "
        << perf_cmdline
        << "\n"
           "and checking that it reports a nonzero number of events.\n"
           "If performance counters seem to be working with 'perf', file an\n"
           "rr issue, otherwise check your hardware/OS/VM configuration. Also\n"
           "check that other software is not using performance counters on\n"
           "this CPU.";
  }

  perf_attr.only_one_counter = events2 == 0;
  LOG(debug) << "only_one_counter=" << perf_attr.only_one_counter;

  if (perf_attr.only_one_counter) {
    arch_check_restricted_counter();
  }
}

static void check_for_bugs(perf_event_attrs &perf_attr) {
  DEBUG_ASSERT(!running_under_rr());

  check_for_ioc_period_bug(perf_attr);
  check_working_counters(perf_attr);
  check_for_arch_bugs(perf_attr);
}

static std::vector<CpuMicroarch> get_cpu_microarchs() {
  string forced_uarch = lowercase(Flags::get().forced_uarch);
  if (!forced_uarch.empty()) {
    for (size_t i = 0; i < array_length(pmu_configs); ++i) {
      const PmuConfig& pmu = pmu_configs[i];
      string name = lowercase(pmu.name);
      if (name.npos != name.find(forced_uarch)) {
        LOG(info) << "Using forced uarch " << pmu.name;
        return { pmu.uarch };
      }
    }
    CLEAN_FATAL() << "Forced uarch " << Flags::get().forced_uarch
                  << " isn't known.";
  }
  return compute_cpu_microarchs();
}

// Similar to rr::perf_attrs, if this contains more than one element,
// it's indexed by the CPU index.
static std::vector<PmuConfig> get_pmu_microarchs() {
  std::vector<PmuConfig> pmu_uarchs;
  auto uarchs = get_cpu_microarchs();
  bool found_working_pmu = false;
  for (auto uarch : uarchs) {
    bool found = false;
    for (size_t i = 0; i < array_length(pmu_configs); ++i) {
      if (uarch == pmu_configs[i].uarch) {
        found = true;
        if (pmu_configs[i].flags & (PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES)) {
          found_working_pmu |= true;
        }
        pmu_uarchs.push_back(pmu_configs[i]);
        break;
      }
    }
    DEBUG_ASSERT(found);
  }
  if (!found_working_pmu) {
    CLEAN_FATAL() << "No supported microarchitectures found.";
  }
  DEBUG_ASSERT(!pmu_uarchs.empty());
  // Note that the `uarch` field after processed by `post_init_pmu_uarchs`
  // is used to store the bug_flags and may not be the actual uarch.
  post_init_pmu_uarchs(pmu_uarchs);
  return pmu_uarchs;
}

static void init_attributes() {
  if (attributes_initialized) {
    return;
  }
  attributes_initialized = true;

  auto pmu_uarchs = get_pmu_microarchs();
  pmu_semantics_flags = PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES;
  for (auto &pmu_uarch : pmu_uarchs) {
    if (!(pmu_uarch.flags & (PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES))) {
      continue;
    }
    pmu_semantics_flags = pmu_semantics_flags & pmu_uarch.flags;
  }
  if (!(pmu_semantics_flags & (PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES))) {
    if (pmu_uarchs.size() == 1) {
      FATAL() << "Microarchitecture `" << pmu_uarchs[0].name
              << "' currently unsupported.";
    } else {
      std::string uarch_list;
      for (auto &pmu_uarch : pmu_uarchs) {
        uarch_list += "\n  ";
        uarch_list += pmu_uarch.name;
      }
      FATAL() << "Microarchitecture combination currently unsupported:"
              << uarch_list;
    }
  }

  if (running_under_rr()) {
    perf_attrs.resize(1);
    init_perf_event_attr(&perf_attrs[0].ticks, PERF_TYPE_HARDWARE, PERF_COUNT_RR);
    perf_attrs[0].skid_size = RR_SKID_MAX;
    perf_attrs[0].pmu_flags = pmu_semantics_flags;
  } else {
    auto npmus = pmu_uarchs.size();
    perf_attrs.resize(npmus);
    for (size_t i = 0; i < npmus; i++) {
      auto &perf_attr = perf_attrs[i];
      auto &pmu_uarch = pmu_uarchs[i];
      if (!(pmu_uarch.flags & (PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES))) {
        perf_attr.pmu_flags = 0; // Mark as unsupported
        continue;
      }
      perf_attr.pmu_name = pmu_uarch.pmu_name;
      perf_attr.skid_size = pmu_uarch.skid_size;
      perf_attr.pmu_flags = pmu_uarch.flags;
      perf_attr.bug_flags = (int)pmu_uarch.uarch;
      init_perf_event_attr(&perf_attr.ticks, pmu_uarch.event_type,
                           pmu_uarch.rcb_cntr_event);
      if (pmu_uarch.minus_ticks_cntr_event != 0) {
        init_perf_event_attr(&perf_attr.minus_ticks, pmu_uarch.event_type,
                             pmu_uarch.minus_ticks_cntr_event);
      }
      init_perf_event_attr(&perf_attr.cycles, pmu_uarch.cycle_type,
                           pmu_uarch.cycle_event);
      init_perf_event_attr(&perf_attr.llsc_fail, pmu_uarch.event_type,
                           pmu_uarch.llsc_cntr_event);
    }
  }
}

bool PerfCounters::support_cpu(int cpu)
{
  // We could probably make cpu=-1 mean whether all CPUs are supported
  // if there's a need for it...
  DEBUG_ASSERT(cpu >= 0);
  init_attributes();

  auto nattrs = (int)perf_attrs.size();
  if (nattrs == 1) {
    cpu = 0;
  }
  if (cpu >= nattrs) {
    return false;
  }
  auto &perf_attr = perf_attrs[cpu];
  return perf_attr.pmu_flags & (PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES);
}

static void check_pmu(int pmu_index) {
  auto &perf_attr = perf_attrs[pmu_index];
  if (perf_attr.checked) {
    return;
  }
  perf_attr.checked = true;

  // Under rr we emulate idealized performance counters, so we can assume
  // none of the bugs apply.
  if (running_under_rr()) {
    return;
  }

  check_for_bugs(perf_attr);
  /*
   * For maintainability, and since it doesn't impact performance when not
   * needed, we always activate this. If it ever turns out to be a problem,
   * this can be set to pmu->flags & PMU_BENEFITS_FROM_USELESS_COUNTER,
   * instead.
   *
   * We also disable this counter when running under rr. Even though it's the
   * same event for the same task as the outer rr, the linux kernel does not
   * coalesce them and tries to schedule the new one on a general purpose PMC.
   * On CPUs with only 2 general PMCs (e.g. KNL), we'd run out.
   */
  perf_attr.activate_useless_counter = perf_attr.has_ioc_period_bug;
}

bool PerfCounters::is_rr_ticks_attr(const perf_event_attr& attr) {
  return attr.type == PERF_TYPE_HARDWARE && attr.config == PERF_COUNT_RR;
}

bool PerfCounters::supports_ticks_semantics(TicksSemantics ticks_semantics) {
  init_attributes();
  switch (ticks_semantics) {
  case TICKS_RETIRED_CONDITIONAL_BRANCHES:
    return (pmu_semantics_flags & PMU_TICKS_RCB) != 0;
  case TICKS_TAKEN_BRANCHES:
    return (pmu_semantics_flags & PMU_TICKS_TAKEN_BRANCHES) != 0;
  default:
    FATAL() << "Unknown ticks_semantics " << ticks_semantics;
    return false;
  }
}

TicksSemantics PerfCounters::default_ticks_semantics() {
  init_attributes();
  if (pmu_semantics_flags & PMU_TICKS_TAKEN_BRANCHES) {
    return TICKS_TAKEN_BRANCHES;
  }
  if (pmu_semantics_flags & PMU_TICKS_RCB) {
    return TICKS_RETIRED_CONDITIONAL_BRANCHES;
  }
  FATAL() << "Unsupported architecture";
  return TICKS_TAKEN_BRANCHES;
}

uint32_t PerfCounters::skid_size() {
  DEBUG_ASSERT(attributes_initialized);
  DEBUG_ASSERT(perf_attrs[pmu_index].checked);
  return perf_attrs[pmu_index].skid_size;
}

PerfCounters::PerfCounters(pid_t tid, int cpu_binding,
                           TicksSemantics ticks_semantics, Enabled enabled,
                           IntelPTEnabled enable_pt)
    : tid(tid), pmu_index(get_pmu_index(cpu_binding)), ticks_semantics_(ticks_semantics),
      enabled(enabled), opened(false), counting(false) {
  if (!supports_ticks_semantics(ticks_semantics)) {
    FATAL() << "Ticks semantics " << ticks_semantics << " not supported";
  }
  if (enable_pt == PT_ENABLE) {
    pt_state = make_unique<PTState>();
  }
}

static void make_counter_async(ScopedFd& fd, int signal) {
  if (fcntl(fd, F_SETFL, O_ASYNC) || fcntl(fd, F_SETSIG, signal)) {
    FATAL() << "Failed to make ticks counter ASYNC with sig"
            << signal_name(signal);
  }
}

static void infallible_perf_event_reset_if_open(ScopedFd& fd) {
  if (fd.is_open()) {
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_RESET) failed";
    }
  }
}

static void infallible_perf_event_enable_if_open(ScopedFd& fd) {
  if (fd.is_open()) {
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_ENABLE) failed";
    }
  }
}

static void infallible_perf_event_disable_if_open(ScopedFd& fd) {
  if (fd.is_open()) {
    if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_ENABLE) failed";
    }
  }
}

static uint32_t pt_event_type() {
  static const char file_name[] = "/sys/bus/event_source/devices/intel_pt/type";
  ScopedFd fd(file_name, O_RDONLY);
  if (!fd.is_open()) {
    FATAL() << "Can't open " << file_name << ", PT events not available";
  }
  char buf[6];
  ssize_t ret = read(fd, buf, sizeof(buf));
  if (ret < 1 || ret > 5) {
    FATAL() << "Invalid value in " << file_name;
  }
  char* end_ptr;
  unsigned long value = strtoul(buf, &end_ptr, 10);
  if (end_ptr < buf + ret && *end_ptr && *end_ptr != '\n') {
    FATAL() << "Invalid value in " << file_name;
  }
  return value;
}

static const size_t PT_PERF_DATA_SIZE = 8*1024*1024;
static const size_t PT_PERF_AUX_SIZE = 128*1024*1024;

struct PTCopyThreadState {
  pthread_mutex_t mutex;
  unordered_set<PerfCounters::PTState*> counting_pt_states;

  PTCopyThreadState() {
    pthread_mutex_init(&mutex, nullptr);
    pthread_t thread;
    pthread_create(&thread, nullptr, do_thread, this);
    pthread_setname_np(thread, "pt_copy");
  }
  void start_copying(PerfCounters::PTState* state) {
    pthread_mutex_lock(&mutex);
    counting_pt_states.insert(state);
    pthread_mutex_unlock(&mutex);
  }
  void stop_copying(PerfCounters::PTState* state) {
    pthread_mutex_lock(&mutex);
    counting_pt_states.erase(state);
    pthread_mutex_unlock(&mutex);
  }

private:
  static void* do_thread(void* p) {
    static_cast<PTCopyThreadState*>(p)->thread_run();
    return nullptr;
  }
  void thread_run() {
    while (true) {
      pthread_mutex_lock(&mutex);
      while (true) {
        bool did_work = false;
        for (PerfCounters::PTState* state : counting_pt_states) {
          size_t bytes = state->flush();
          if (bytes > 0) {
            did_work = true;
          }
        }
        if (!did_work) {
          break;
        }
      }
      pthread_mutex_unlock(&mutex);

      struct timespec ts = { 0, 250000 };
      nanosleep(&ts, nullptr);
    }
  }
};

static PTCopyThreadState* pt_thread_state;

void PerfCounters::start_pt_copy_thread() {
  if (!pt_thread_state) {
    pt_thread_state = new PTCopyThreadState();
  }
}

// See https://github.com/intel/libipt/blob/master/doc/howto_capture.md
void PerfCounters::PTState::open(pid_t tid) {
  static uint32_t event_type = pt_event_type();

  struct perf_event_attr attr;
  init_perf_event_attr(&attr, event_type, 0);
  attr.aux_watermark = 8 * 1024 * 1024;
  pt_perf_event_fd = start_counter(tid, -1, &attr);
  if (!pt_perf_event_fd.is_open()) {
    return;
  }

  perf_buffers.allocate(pt_perf_event_fd, PT_PERF_DATA_SIZE, PT_PERF_AUX_SIZE);
}

size_t PerfCounters::PTState::flush() {
  if (!perf_buffers.allocated()) {
    return 0;
  }

  size_t ret = 0;

  while (auto packet = perf_buffers.next_packet()) {
    struct perf_event_header header = *packet->data();
    switch (header.type) {
      case PERF_RECORD_LOST:
        FATAL() << "PT records lost!";
        break;
      case PERF_RECORD_ITRACE_START:
        break;
      case PERF_RECORD_AUX: {
        auto aux_packet = *reinterpret_cast<PerfEventAux*>(packet->data());
        if (aux_packet.flags) {
          FATAL() << "Unexpected AUX packet flags " << aux_packet.flags;
        }
        pt_data.data.emplace_back();
        vector<uint8_t>& data = pt_data.data.back();
        data.resize(aux_packet.aux_size);
        memcpy(data.data(), packet->aux_data(), aux_packet.aux_size);
        ret += aux_packet.aux_size;
        break;
      }
      default:
        FATAL() << "Unknown record " << header.type;
        break;
    }
  }

  return ret;
}

PTData PerfCounters::extract_intel_pt_data() {
  PTData result;
  if (pt_state) {
    result = std::move(pt_state->pt_data);
  }
  return result;
}

void PerfCounters::PTState::close() {
  pt_perf_event_fd.close();
  perf_buffers.destroy();
}

void PerfCounters::start(Task* t, Ticks ticks_period) {
  ASSERT(t, !counting);
  ASSERT(t, ticks_period >= 0);

  if (enabled == DISABLE) {
    return;
  }

  check_pmu(pmu_index);

  auto &perf_attr = perf_attrs[pmu_index];
  if (ticks_period == 0) {
    // We can't switch a counter between sampling and non-sampling via
    // PERF_EVENT_IOC_PERIOD so just turn 0 into a very big number.
    ticks_period = uint64_t(1) << 60;
  }

  if (!opened) {
    LOG(debug) << "Recreating counters with period " << ticks_period;

    struct perf_event_attr attr = perf_attr.ticks;
    struct perf_event_attr minus_attr = perf_attr.minus_ticks;
    attr.sample_period = ticks_period;
    fd_ticks_interrupt = start_counter(tid, -1, &attr);
    if (minus_attr.config != 0) {
      fd_minus_ticks_measure = start_counter(tid, fd_ticks_interrupt, &minus_attr);
    }

    if (!perf_attr.only_one_counter && !running_under_rr()) {
      reset_arch_extras<NativeArch>();
    }

    if (perf_attr.activate_useless_counter && !fd_useless_counter.is_open()) {
      // N.B.: This is deliberately not in the same group as the other counters
      // since we want to keep it scheduled at all times.
      fd_useless_counter = start_counter(tid, -1, &perf_attr.cycles);
    }

    if (fd_ticks_interrupt.is_open()) {
      struct f_owner_ex own;
      own.type = F_OWNER_TID;
      own.pid = tid;
      if (fcntl(fd_ticks_interrupt, F_SETOWN_EX, &own)) {
        FATAL() << "Failed to SETOWN_EX ticks event fd";
      }
      make_counter_async(fd_ticks_interrupt, PerfCounters::TIME_SLICE_SIGNAL);
    }

    if (pt_state) {
      pt_state->open(tid);
      pt_thread_state->start_copying(pt_state.get());
    }
  } else {
    LOG(debug) << "Resetting counters with period " << ticks_period;

    infallible_perf_event_reset_if_open(fd_ticks_interrupt);
    if (ioctl(fd_ticks_interrupt, PERF_EVENT_IOC_PERIOD, &ticks_period)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_PERIOD) failed with period "
              << ticks_period;
    }
    infallible_perf_event_enable_if_open(fd_ticks_interrupt);

    infallible_perf_event_reset_if_open(fd_minus_ticks_measure);
    infallible_perf_event_enable_if_open(fd_minus_ticks_measure);

    infallible_perf_event_reset_if_open(fd_ticks_measure);
    infallible_perf_event_enable_if_open(fd_ticks_measure);

    infallible_perf_event_reset_if_open(fd_ticks_in_transaction);
    infallible_perf_event_enable_if_open(fd_ticks_in_transaction);

    if (pt_state) {
      infallible_perf_event_enable_if_open(pt_state->pt_perf_event_fd);
      pt_thread_state->start_copying(pt_state.get());
    }
  }

  opened = true;
  counting = true;
  counting_period = ticks_period;
}

void PerfCounters::set_tid(pid_t tid) {
  close();
  this->tid = tid;
}

void PerfCounters::close() {
  if (counting) {
    FATAL() << "Can't close while counting task " << tid;
  }

  if (!opened) {
    return;
  }
  opened = false;
  if (pt_state) {
    pt_state->close();
  }

  fd_ticks_interrupt.close();
  fd_ticks_measure.close();
  fd_minus_ticks_measure.close();
  fd_useless_counter.close();
  fd_ticks_in_transaction.close();
  fd_async_signal_accelerator.close();
}

Ticks PerfCounters::stop(Task* t, Error* error) {
  if (!counting) {
    if (error) {
      *error = Error::None;
    }
    return 0;
  }

  Ticks ticks = read_ticks(t, error);
  counting = false;
  if (pt_state) {
    pt_thread_state->stop_copying(pt_state.get());
    pt_state->flush();
  }
  if (always_recreate_counters(perf_attrs[pmu_index])) {
    close();
  } else {
    infallible_perf_event_disable_if_open(fd_ticks_interrupt);
    infallible_perf_event_disable_if_open(fd_minus_ticks_measure);
    infallible_perf_event_disable_if_open(fd_ticks_measure);
    infallible_perf_event_disable_if_open(fd_ticks_in_transaction);
    if (pt_state) {
      infallible_perf_event_disable_if_open(pt_state->pt_perf_event_fd);
    }
    infallible_perf_event_disable_if_open(fd_async_signal_accelerator);
  }
  return ticks;
}

// Note that on aarch64 this is also used to get the count for `ret`
Ticks PerfCounters::ticks_for_unconditional_indirect_branch(Task*) {
  DEBUG_ASSERT(attributes_initialized);
  return (pmu_semantics_flags & PMU_TICKS_TAKEN_BRANCHES) ? 1 : 0;
}

Ticks PerfCounters::ticks_for_unconditional_direct_branch(Task*) {
  DEBUG_ASSERT(attributes_initialized);
  return (pmu_semantics_flags & PMU_TICKS_TAKEN_BRANCHES) ? 1 : 0;
}

Ticks PerfCounters::ticks_for_direct_call(Task*) {
  DEBUG_ASSERT(attributes_initialized);
  return (pmu_semantics_flags & PMU_TICKS_TAKEN_BRANCHES) ? 1 : 0;
}

Ticks PerfCounters::read_ticks(Task* t, Error* error) {
  if (error) {
    *error = Error::None;
  }

  ASSERT(t, opened);
  ASSERT(t, counting);
  ASSERT(t, counting_period > 0);

  if (fd_ticks_in_transaction.is_open()) {
    uint64_t transaction_ticks = read_counter(fd_ticks_in_transaction);
    if (transaction_ticks > 0) {
      LOG(debug) << transaction_ticks << " IN_TX ticks detected";
      if (!Flags::get().force_things) {
        ASSERT(t, false)
            << transaction_ticks
            << " IN_TX ticks detected while HLE not supported due to KVM PMU\n"
               "virtualization bug. See "
               "http://marc.info/?l=linux-kernel&m=148582794808419&w=2\n"
               "Aborting. Retry with -F to override, but it will probably\n"
               "fail.";
      }
    }
  }

  if (fd_strex_counter.is_open()) {
    uint64_t strex_count = read_counter(fd_strex_counter);
    if (strex_count > 0) {
      LOG(debug) << strex_count << " strex detected";
      if (!Flags::get().force_things) {
        ASSERT(t, false)
            << strex_count
            << " (speculatively) executed strex instructions detected. \n"
               "On aarch64, rr only supports applications making use of LSE\n"
               "atomics rather than legacy LL/SC-based atomics.\n"
               "Aborting. Retry with -F to override, but replaying such\n"
               "a recording will probably fail.";
      }
    }
  }

  uint64_t adjusted_counting_period =
      counting_period +
      (t->session().is_recording() ? recording_skid_size() : skid_size());
  uint64_t interrupt_val = 0;
  if (fd_ticks_interrupt.is_open()) {
    interrupt_val = read_counter(fd_ticks_interrupt);
  }
  uint64_t ret;
  if (!fd_ticks_measure.is_open()) {
    if (fd_minus_ticks_measure.is_open()) {
      uint64_t minus_measure_val = read_counter(fd_minus_ticks_measure);
      interrupt_val -= minus_measure_val;
    }
    if (t->session().is_recording()) {
      if (interrupt_val > adjusted_counting_period) {
        LOG(warn) << "Recorded ticks of " << interrupt_val
          << " overshot requested ticks target by " << interrupt_val - counting_period
          << " ticks.\n"
           "On AMD systems this is known to occur occasionally for unknown reasons.\n"
           "Recording should continue normally. Please report any unexpected rr failures\n"
           "received after this warning, any conditions that reliably reproduce it,\n"
           "or sightings of this warning on non-AMD systems.";
      }
    }
    ret = interrupt_val;
  } else {
    uint64_t measure_val = read_counter(fd_ticks_measure);
    if (measure_val > interrupt_val) {
      // There is some kind of kernel or hardware bug that means we sometimes
      // see more events with IN_TXCP set than without. These are clearly
      // spurious events :-(. For now, work around it by returning the
      // interrupt_val. That will work if HLE hasn't been used in this interval.
      // Note that interrupt_val > measure_val is valid behavior (when HLE is
      // being used).
      LOG(debug) << "Measured too many ticks; measure=" << measure_val
                 << ", interrupt=" << interrupt_val;
      ret = interrupt_val;
    } else {
      ret = measure_val;
    }
  }
  if (!t->session().is_recording() && ret > adjusted_counting_period) {
    if (error && (perf_attrs[pmu_index].pmu_flags & PMU_SKID_UNBOUNDED)) {
      *error = Error::Transient;
    } else {
      ASSERT(t, false) << "Detected " << ret
          << " ticks, expected no more than " << adjusted_counting_period;
    }
  }
  return ret;
}

#ifdef BPF
class BpfAccelerator {
public:
  static std::shared_ptr<BpfAccelerator> get_or_create();

  ScopedFd create_counter(pid_t tid);
  void match_regs_and_open_counter(const Registers& regs, ScopedFd& counter);
  uint64_t skips() const {
    return *bpf_skips;
  }

  // Can't be private because of make_shared.
  BpfAccelerator(struct bpf_object* bpf_obj, int bpf_prog_fd,
                 user_regs_struct* bpf_regs, uint64_t* bpf_skips)
    : bpf_obj(bpf_obj), bpf_prog_fd(bpf_prog_fd), bpf_regs(bpf_regs), bpf_skips(bpf_skips)
  {}

  ~BpfAccelerator() {
    munmap(bpf_skips, 4096);
    munmap(bpf_regs, 4096);
    bpf_object__close(bpf_obj);
  }

private:
  static std::shared_ptr<BpfAccelerator> singleton;

  struct perf_event_attr attr;
  struct bpf_object* bpf_obj;
  // Not a ScopedFd because the bpf_object maintains ownership.
  int bpf_prog_fd;
  user_regs_struct* bpf_regs;
  uint64_t* bpf_skips;
};

std::shared_ptr<BpfAccelerator> BpfAccelerator::singleton;

/* static */ std::shared_ptr<BpfAccelerator> BpfAccelerator::get_or_create() {
  static int initialized;
  if (BpfAccelerator::singleton) {
    return BpfAccelerator::singleton;
  }

  if (!initialized) {
    initialized = -1;

    libbpf_set_strict_mode(LIBBPF_STRICT_DIRECT_ERRS);
    string path = resource_path() + "share/rr/async_event_filter.o";
    struct bpf_object* obj = bpf_object__open(path.c_str());
    if ((intptr_t)obj <= 0) {
      LOG(error) << "Failed to find bpf at " << path;
      return nullptr;
    }
    if (bpf_object__load(obj) < 0) {
      LOG(error) << "Failed to load bpf at " << path << " into the kernel. Do we have permissions?";
      bpf_object__close(obj);
      return nullptr;
    }
    int bpf_map_fd = bpf_object__find_map_fd_by_name(obj, "registers");
    if (bpf_map_fd < 0) {
      CLEAN_FATAL() << "rr's bpf at " << path << " is corrupt";
      return nullptr;
    }
    struct bpf_program* prog = bpf_object__next_program(obj, nullptr);
    if (!prog) {
      CLEAN_FATAL() << "rr's bpf at " << path << " is corrupt";
      return nullptr;
    }
    int bpf_prog_fd = bpf_program__fd(prog);
    if (bpf_prog_fd < 0) {
      CLEAN_FATAL() << "rr's bpf at " << path << " is corrupt";
      return nullptr;
    }

    auto bpf_regs = (struct user_regs_struct*)
      mmap(NULL, 4096, PROT_READ | PROT_WRITE,
           MAP_SHARED, bpf_map_fd, 0);
    if (bpf_regs == MAP_FAILED) {
      CLEAN_FATAL() << "Failed to mmap bpf maps";
      return nullptr;
    }

    bpf_map_fd = bpf_object__find_map_fd_by_name(obj, "skips");
    if (bpf_map_fd < 0) {
      CLEAN_FATAL() << "rr's bpf at " << path << " is corrupt";
      return nullptr;
    }

    auto bpf_skips = (uint64_t*)
      mmap(NULL, 4096, PROT_READ | PROT_WRITE,
           MAP_SHARED, bpf_map_fd, 0);
    if (bpf_regs == MAP_FAILED) {
      CLEAN_FATAL() << "Failed to mmap bpf maps";
      return nullptr;
    }

    BpfAccelerator::singleton =
      std::make_shared<BpfAccelerator>(obj, bpf_prog_fd, bpf_regs, bpf_skips);
    memset(&singleton->attr, 0, sizeof(singleton->attr));
    singleton->attr.type = PERF_TYPE_BREAKPOINT;
    singleton->attr.size = sizeof(attr);
    singleton->attr.bp_type = HW_BREAKPOINT_X;
    singleton->attr.bp_len = sizeof(long);
    singleton->attr.sample_period = 1;
    singleton->attr.sample_type = PERF_SAMPLE_IP;
    singleton->attr.pinned = 1;
    singleton->attr.exclude_kernel = 1;
    singleton->attr.exclude_hv = 1;
    singleton->attr.wakeup_events = 1;
    singleton->attr.precise_ip = 3;
    singleton->attr.disabled = 1;
    initialized = 1;
  }

  return BpfAccelerator::singleton;
}

ScopedFd BpfAccelerator::create_counter(pid_t tid) {
  attr.bp_addr = 0;
  ScopedFd fd = start_counter(tid, -1, &attr);

  struct f_owner_ex own;
  own.type = F_OWNER_TID;
  own.pid = tid;
  if (fcntl(fd, F_SETOWN_EX, &own)) {
    FATAL() << "Failed to SETOWN_EX bpf-accelerated breakpoint fd";
  }

  make_counter_async(fd, SIGTRAP);

  if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, bpf_prog_fd)) {
    FATAL() << "Failed PERF_EVENT_IOC_SET_BPF";
  }

  return fd;
}

void BpfAccelerator::match_regs_and_open_counter(const Registers& regs, ScopedFd& fd) {
  attr.bp_addr = regs.ip().register_value();
  if (ioctl(fd, PERF_EVENT_IOC_MODIFY_ATTRIBUTES, &attr)) {
    FATAL() << "Failed PERF_EVENT_IOC_MODIFY_ATTRIBUTES";
  }

  auto r = regs.get_ptrace();
  memcpy(bpf_regs, &r, sizeof(struct user_regs_struct));
  *bpf_skips = 0;

  infallible_perf_event_enable_if_open(fd);
}

bool PerfCounters::accelerate_async_signal(const Registers& regs) {
  if (!fd_async_signal_accelerator.is_open()) {
    if (!bpf) {
      bpf = BpfAccelerator::get_or_create();
    }

    if (!bpf) {
      return false;
    }

    fd_async_signal_accelerator = bpf->create_counter(tid);
  }

  if (!fd_async_signal_accelerator.is_open()) {
    return false;
  }

  bpf->match_regs_and_open_counter(regs, fd_async_signal_accelerator);
  return true;
}

uint64_t PerfCounters::bpf_skips() const {
  if (!bpf) {
    return 0;
  }

  return bpf->skips();
}
#endif

} // namespace rr
