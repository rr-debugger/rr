/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "PerfCounters.h"

#include <err.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <string>

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
static struct perf_event_attr ticks_attr;
static struct perf_event_attr minus_ticks_attr;
static struct perf_event_attr cycles_attr;
static struct perf_event_attr hw_interrupts_attr;
static struct perf_event_attr llsc_fail_attr;
static uint32_t pmu_flags;
static uint32_t skid_size;
static bool has_ioc_period_bug;
static bool only_one_counter;
static bool activate_useless_counter;

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
  IntelKabylake,
  IntelCometlake,
  IntelIcelake,
  LastIntel = IntelIcelake,
  FirstAMD,
  AMDF15R30 = FirstAMD,
  AMDZen,
  LastAMD = AMDZen,
  FirstARM,
  ARMNeoverseN1 = FirstARM,
  LastARM = ARMNeoverseN1,
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
  unsigned hw_intr_cntr_event;
  unsigned llsc_cntr_event;
  uint32_t skid_size;
  uint32_t flags;
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
  { IntelIcelake, "Intel Icelake", 0x5111c4, 0, 0, 0, 100, PMU_TICKS_RCB },
  { IntelCometlake, "Intel Cometlake", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelKabylake, "Intel Kabylake", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelSilvermont, "Intel Silvermont", 0x517ec4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelGoldmont, "Intel Goldmont", 0x517ec4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelSkylake, "Intel Skylake", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelBroadwell, "Intel Broadwell", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelHaswell, "Intel Haswell", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelIvyBridge, "Intel Ivy Bridge", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelSandyBridge, "Intel Sandy Bridge", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelNehalem, "Intel Nehalem", 0x5101c4, 0, 0x50011d, 0, 100, PMU_TICKS_RCB },
  { IntelWestmere, "Intel Westmere", 0x5101c4, 0, 0x50011d, 0, 100, PMU_TICKS_RCB },
  { IntelPenryn, "Intel Penryn", 0, 0, 0, 0, 100, 0 },
  { IntelMerom, "Intel Merom", 0, 0, 0, 0, 100, 0 },
  { AMDF15R30, "AMD Family 15h Revision 30h", 0xc4, 0xc6, 0, 0, 250, PMU_TICKS_TAKEN_BRANCHES },
  // 0xd1 == RETIRED_CONDITIONAL_BRANCH_INSTRUCTIONS - Number of retired conditional branch instructions
  // 0x2c == INTERRUPT_TAKEN - Counts the number of interrupts taken
  // Both counters are available on Zen, Zen+ and Zen2.
  { AMDZen, "AMD Zen", 0x5100d1, 0, 0x51002c, 0, 10000, PMU_TICKS_RCB },
  // 0x21 == BR_RETIRED - Architecturally retired taken branches
  // 0x6F == STREX_SPEC - Speculatively executed strex instructions
  { ARMNeoverseN1, "ARM Neoverse N1", 0x21, 0, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES }
};

#define RR_SKID_MAX 10000

static string lowercase(const string& s) {
  string c = s;
  transform(c.begin(), c.end(), c.begin(), ::tolower);
  return c;
}

static void init_perf_event_attr(struct perf_event_attr* attr,
                                 perf_type_id type, unsigned config) {
  memset(attr, 0, sizeof(*attr));
  attr->type = type;
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

static ScopedFd start_counter(pid_t tid, int group_fd,
                              struct perf_event_attr* attr,
                              bool* disabled_txcp = nullptr) {
  if (disabled_txcp) {
    *disabled_txcp = false;
  }
  attr->pinned = group_fd == -1;
  int fd = syscall(__NR_perf_event_open, attr, tid, -1, group_fd, PERF_FLAG_FD_CLOEXEC);
  if (0 >= fd && errno == EINVAL && attr->type == PERF_TYPE_RAW &&
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
  if (0 >= fd) {
    if (errno == EACCES) {
      FATAL() << "Permission denied to use 'perf_event_open'; are perf events "
                 "enabled? Try 'perf record'.";
    }
    if (errno == ENOENT) {
      FATAL() << "Unable to open performance counter with 'perf_event_open'; "
                 "are perf events enabled? Try 'perf record'.";
    }
    FATAL() << "Failed to initialize counter";
  }
  return fd;
}

static void check_for_ioc_period_bug() {
  // Start a cycles counter
  struct perf_event_attr attr = rr::ticks_attr;
  attr.sample_period = 0xffffffff;
  attr.exclude_kernel = 1;
  ScopedFd bug_fd = start_counter(0, -1, &attr);

  uint64_t new_period = 1;
  if (ioctl(bug_fd, PERF_EVENT_IOC_PERIOD, &new_period)) {
    FATAL() << "ioctl(PERF_EVENT_IOC_PERIOD) failed";
  }

  struct pollfd poll_bug_fd = {.fd = bug_fd, .events = POLL_IN, .revents = 0 };
  poll(&poll_bug_fd, 1, 0);

  has_ioc_period_bug = poll_bug_fd.revents == 0;
  LOG(debug) << "has_ioc_period_bug=" << has_ioc_period_bug;
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

static void check_working_counters() {
  struct perf_event_attr attr = rr::ticks_attr;
  attr.sample_period = 0;
  struct perf_event_attr attr2 = rr::cycles_attr;
  attr.sample_period = 0;
  ScopedFd fd = start_counter(0, -1, &attr);
  ScopedFd fd2 = start_counter(0, -1, &attr2);
  do_branches();
  int64_t events = read_counter(fd);
  int64_t events2 = read_counter(fd2);

  if (events < NUM_BRANCHES) {
    char config[100];
    sprintf(config, "%llx", (long long)ticks_attr.config);
    FATAL()
        << "\nGot " << events << " branch events, expected at least "
        << NUM_BRANCHES
        << ".\n"
           "\nThe hardware performance counter seems to not be working. Check\n"
           "that hardware performance counters are working by running\n"
           "  perf stat -e r"
        << config
        << " true\n"
           "and checking that it reports a nonzero number of events.\n"
           "If performance counters seem to be working with 'perf', file an\n"
           "rr issue, otherwise check your hardware/OS/VM configuration. Also\n"
           "check that other software is not using performance counters on\n"
           "this CPU.";
  }

  only_one_counter = events2 == 0;
  LOG(debug) << "only_one_counter=" << only_one_counter;

  if (only_one_counter) {
    arch_check_restricted_counter();
  }
}

static void check_for_bugs(CpuMicroarch uarch) {
  if (running_under_rr()) {
    // Under rr we emulate idealized performance counters, so we can assume
    // none of the bugs apply.
    return;
  }

  check_for_ioc_period_bug();
  check_working_counters();
  check_for_arch_bugs(uarch);
}

static CpuMicroarch get_cpu_microarch() {
  string forced_uarch = lowercase(Flags::get().forced_uarch);
  if (!forced_uarch.empty()) {
    for (size_t i = 0; i < array_length(pmu_configs); ++i) {
      const PmuConfig& pmu = pmu_configs[i];
      string name = lowercase(pmu.name);
      if (name.npos != name.find(forced_uarch)) {
        LOG(info) << "Using forced uarch " << pmu.name;
        return pmu.uarch;
      }
    }
    CLEAN_FATAL() << "Forced uarch " << Flags::get().forced_uarch
                  << " isn't known.";
  }
  return compute_cpu_microarch();
}

static void init_attributes() {
  if (attributes_initialized) {
    return;
  }
  attributes_initialized = true;

  CpuMicroarch uarch = get_cpu_microarch();
  const PmuConfig* pmu = nullptr;
  for (size_t i = 0; i < array_length(pmu_configs); ++i) {
    if (uarch == pmu_configs[i].uarch) {
      pmu = &pmu_configs[i];
      break;
    }
  }
  DEBUG_ASSERT(pmu);

  if (!(pmu->flags & (PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES))) {
    FATAL() << "Microarchitecture `" << pmu->name << "' currently unsupported.";
  }

  if (running_under_rr()) {
    init_perf_event_attr(&ticks_attr, PERF_TYPE_HARDWARE, PERF_COUNT_RR);
    skid_size = RR_SKID_MAX;
    pmu_flags = pmu->flags & (PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES);
  } else {
    skid_size = pmu->skid_size;
    pmu_flags = pmu->flags;
    init_perf_event_attr(&ticks_attr, PERF_TYPE_RAW, pmu->rcb_cntr_event);
    if (pmu->minus_ticks_cntr_event != 0) {
      init_perf_event_attr(&minus_ticks_attr, PERF_TYPE_RAW,
                           pmu->minus_ticks_cntr_event);
    }
    init_perf_event_attr(&cycles_attr, PERF_TYPE_HARDWARE,
                         PERF_COUNT_HW_CPU_CYCLES);
    init_perf_event_attr(&hw_interrupts_attr, PERF_TYPE_RAW,
                         pmu->hw_intr_cntr_event);
    init_perf_event_attr(&llsc_fail_attr, PERF_TYPE_RAW,
                         pmu->llsc_cntr_event);
    // libpfm encodes the event with this bit set, so we'll do the
    // same thing.  Unclear if necessary.
    hw_interrupts_attr.exclude_hv = 1;

    check_for_bugs(uarch);
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
    activate_useless_counter = has_ioc_period_bug && !running_under_rr();
  }
}

bool PerfCounters::is_rr_ticks_attr(const perf_event_attr& attr) {
  return attr.type == PERF_TYPE_HARDWARE && attr.config == PERF_COUNT_RR;
}

bool PerfCounters::supports_ticks_semantics(TicksSemantics ticks_semantics) {
  init_attributes();
  switch (ticks_semantics) {
  case TICKS_RETIRED_CONDITIONAL_BRANCHES:
    return (pmu_flags & PMU_TICKS_RCB) != 0;
  case TICKS_TAKEN_BRANCHES:
    return (pmu_flags & PMU_TICKS_TAKEN_BRANCHES) != 0;
  default:
    FATAL() << "Unknown ticks_semantics " << ticks_semantics;
    return false;
  }
}

TicksSemantics PerfCounters::default_ticks_semantics() {
  init_attributes();
  if (pmu_flags & PMU_TICKS_TAKEN_BRANCHES) {
    return TICKS_TAKEN_BRANCHES;
  }
  if (pmu_flags & PMU_TICKS_RCB) {
    return TICKS_RETIRED_CONDITIONAL_BRANCHES;
  }
  FATAL() << "Unsupported architecture";
  return TICKS_TAKEN_BRANCHES;
}

uint32_t PerfCounters::skid_size() {
  init_attributes();
  return rr::skid_size;
}

PerfCounters::PerfCounters(pid_t tid, TicksSemantics ticks_semantics)
    : tid(tid), ticks_semantics_(ticks_semantics), started(false), counting(false) {
  if (!supports_ticks_semantics(ticks_semantics)) {
    FATAL() << "Ticks semantics " << ticks_semantics << " not supported";
  }
}

static void make_counter_async(ScopedFd& fd, int signal) {
  if (fcntl(fd, F_SETFL, O_ASYNC) || fcntl(fd, F_SETSIG, signal)) {
    FATAL() << "Failed to make ticks counter ASYNC with sig"
            << signal_name(signal);
  }
}

void PerfCounters::reset(Ticks ticks_period) {
  DEBUG_ASSERT(ticks_period >= 0);

  if (ticks_period == 0 && !always_recreate_counters()) {
    // We can't switch a counter between sampling and non-sampling via
    // PERF_EVENT_IOC_PERIOD so just turn 0 into a very big number.
    ticks_period = uint64_t(1) << 60;
  }

  if (!started) {
    LOG(debug) << "Recreating counters with period " << ticks_period;

    struct perf_event_attr attr = rr::ticks_attr;
    struct perf_event_attr minus_attr = rr::minus_ticks_attr;
    attr.sample_period = ticks_period;
    fd_ticks_interrupt = start_counter(tid, -1, &attr);
    if (minus_attr.config != 0) {
      fd_minus_ticks_measure = start_counter(tid, fd_ticks_interrupt, &minus_attr);
    }

    if (!only_one_counter && !running_under_rr()) {
      reset_arch_extras<NativeArch>();
    }

    if (activate_useless_counter && !fd_useless_counter.is_open()) {
      // N.B.: This is deliberately not in the same group as the other counters
      // since we want to keep it scheduled at all times.
      fd_useless_counter = start_counter(tid, -1, &cycles_attr);
    }

    struct f_owner_ex own;
    own.type = F_OWNER_TID;
    own.pid = tid;
    if (fcntl(fd_ticks_interrupt, F_SETOWN_EX, &own)) {
      FATAL() << "Failed to SETOWN_EX ticks event fd";
    }
    make_counter_async(fd_ticks_interrupt, PerfCounters::TIME_SLICE_SIGNAL);
  } else {
    LOG(debug) << "Resetting counters with period " << ticks_period;

    if (ioctl(fd_ticks_interrupt, PERF_EVENT_IOC_RESET, 0)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_RESET) failed";
    }
    if (ioctl(fd_ticks_interrupt, PERF_EVENT_IOC_PERIOD, &ticks_period)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_PERIOD) failed with period "
              << ticks_period;
    }
    if (ioctl(fd_ticks_interrupt, PERF_EVENT_IOC_ENABLE, 0)) {
      FATAL() << "ioctl(PERF_EVENT_IOC_ENABLE) failed";
    }
    if (fd_minus_ticks_measure.is_open()) {
      if (ioctl(fd_minus_ticks_measure, PERF_EVENT_IOC_RESET, 0)) {
        FATAL() << "ioctl(PERF_EVENT_IOC_RESET) failed";
      }
      if (ioctl(fd_minus_ticks_measure, PERF_EVENT_IOC_ENABLE, 0)) {
        FATAL() << "ioctl(PERF_EVENT_IOC_ENABLE) failed";
      }
    }
    if (fd_ticks_measure.is_open()) {
      if (ioctl(fd_ticks_measure, PERF_EVENT_IOC_RESET, 0)) {
        FATAL() << "ioctl(PERF_EVENT_IOC_RESET) failed";
      }
      if (ioctl(fd_ticks_measure, PERF_EVENT_IOC_ENABLE, 0)) {
        FATAL() << "ioctl(PERF_EVENT_IOC_ENABLE) failed";
      }
    }
    if (fd_ticks_in_transaction.is_open()) {
      if (ioctl(fd_ticks_in_transaction, PERF_EVENT_IOC_RESET, 0)) {
        FATAL() << "ioctl(PERF_EVENT_IOC_RESET) failed";
      }
      if (ioctl(fd_ticks_in_transaction, PERF_EVENT_IOC_ENABLE, 0)) {
        FATAL() << "ioctl(PERF_EVENT_IOC_ENABLE) failed";
      }
    }
  }

  started = true;
  counting = true;
  counting_period = ticks_period;
}

void PerfCounters::set_tid(pid_t tid) {
  stop();
  this->tid = tid;
}

void PerfCounters::stop() {
  if (!started) {
    return;
  }
  started = false;

  fd_ticks_interrupt.close();
  fd_ticks_measure.close();
  fd_minus_ticks_measure.close();
  fd_useless_counter.close();
  fd_ticks_in_transaction.close();
}

void PerfCounters::stop_counting() {
  if (!counting) {
    return;
  }
  counting = false;
  if (always_recreate_counters()) {
    stop();
  } else {
    ioctl(fd_ticks_interrupt, PERF_EVENT_IOC_DISABLE, 0);
    if (fd_minus_ticks_measure.is_open()) {
      ioctl(fd_minus_ticks_measure, PERF_EVENT_IOC_DISABLE, 0);
    }
    if (fd_ticks_measure.is_open()) {
      ioctl(fd_ticks_measure, PERF_EVENT_IOC_DISABLE, 0);
    }
    if (fd_ticks_in_transaction.is_open()) {
      ioctl(fd_ticks_in_transaction, PERF_EVENT_IOC_DISABLE, 0);
    }
  }
}

Ticks PerfCounters::ticks_for_unconditional_indirect_branch(Task*) {
  return (pmu_flags & PMU_TICKS_TAKEN_BRANCHES) ? 1 : 0;
}

Ticks PerfCounters::ticks_for_direct_call(Task*) {
  return (pmu_flags & PMU_TICKS_TAKEN_BRANCHES) ? 1 : 0;
}

Ticks PerfCounters::read_ticks(Task* t) {
  if (!started || !counting) {
    return 0;
  }

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
        CLEAN_FATAL()
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
  uint64_t interrupt_val = read_counter(fd_ticks_interrupt);
  if (!fd_ticks_measure.is_open()) {
    if (fd_minus_ticks_measure.is_open()) {
      uint64_t minus_measure_val = read_counter(fd_minus_ticks_measure);
      interrupt_val -= minus_measure_val;
    }
    ASSERT(t, !counting_period || interrupt_val <= adjusted_counting_period)
        << "Detected " << interrupt_val << " ticks, expected no more than "
        << adjusted_counting_period;
    return interrupt_val;
  }

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
    ASSERT(t, !counting_period || interrupt_val <= adjusted_counting_period)
        << "Detected " << interrupt_val << " ticks, expected no more than "
        << adjusted_counting_period;
    return interrupt_val;
  }
  ASSERT(t, !counting_period || measure_val <= adjusted_counting_period)
      << "Detected " << measure_val << " ticks, expected no more than "
      << adjusted_counting_period;
  return measure_val;
}

} // namespace rr
