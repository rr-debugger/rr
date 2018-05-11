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

static bool attributes_initialized;
static struct perf_event_attr ticks_attr;
static struct perf_event_attr cycles_attr;
static struct perf_event_attr hw_interrupts_attr;
static uint32_t skid_size;
static bool has_ioc_period_bug;
static bool has_kvm_in_txcp_bug;
static bool has_xen_pmi_bug;
static bool supports_txcp;
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
  IntelMerom,
  IntelPenryn,
  IntelNehalem,
  IntelWestmere,
  IntelSandyBridge,
  IntelIvyBridge,
  IntelHaswell,
  IntelBroadwell,
  IntelSkylake,
  IntelSilvermont,
  IntelKabylake,
  AMDRyzen,
};

struct PmuConfig {
  CpuMicroarch uarch;
  const char* name;
  unsigned rcb_cntr_event;
  unsigned hw_intr_cntr_event;
  uint32_t skid_size;
  bool supported;
  /*
   * Some CPUs turn off the whole PMU when there are no remaining events
   * scheduled (perhaps as a power consumption optimization). This can be a
   * very expensive operation, and is thus best avoided. For cpus, where this
   * is a problem, we keep a cycles counter (which corresponds to one of the
   * fixed function counters, so we don't use up a programmable PMC) that we
   * don't otherwise use, but keeps the PMU active, greatly increasing
   * performance.
   */
  bool benefits_from_useless_counter;
};

// XXX please only edit this if you really know what you're doing.
static const PmuConfig pmu_configs[] = {
  { IntelKabylake, "Intel Kabylake", 0x5101c4, 0x5301cb, 100, true, false },
  { IntelSilvermont, "Intel Silvermont", 0x517ec4, 0x5301cb, 100, true, true },
  { IntelSkylake, "Intel Skylake", 0x5101c4, 0x5301cb, 100, true, false },
  { IntelBroadwell, "Intel Broadwell", 0x5101c4, 0x5301cb, 100, true, false },
  { IntelHaswell, "Intel Haswell", 0x5101c4, 0x5301cb, 100, true, false },
  { IntelIvyBridge, "Intel Ivy Bridge", 0x5101c4, 0x5301cb, 100, true, false },
  { IntelSandyBridge, "Intel Sandy Bridge", 0x5101c4, 0x5301cb, 100, true,
    false },
  { IntelNehalem, "Intel Nehalem", 0x5101c4, 0x50011d, 100, true, false },
  { IntelWestmere, "Intel Westmere", 0x5101c4, 0x50011d, 100, true, false },
  { IntelPenryn, "Intel Penryn", 0, 0, 100, false, false },
  { IntelMerom, "Intel Merom", 0, 0, 100, false, false },
  { AMDRyzen, "AMD Ryzen", 0x5100d1, 0, 1000, true, false },
};

static string lowercase(const string& s) {
  string c = s;
  transform(c.begin(), c.end(), c.begin(), ::tolower);
  return c;
}

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 */
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

  auto cpuid_vendor = cpuid(CPUID_GETVENDORSTRING, 0);
  char vendor[13];
  memcpy(&vendor[0], &cpuid_vendor.ebx, 4);
  memcpy(&vendor[4], &cpuid_vendor.edx, 4);
  memcpy(&vendor[8], &cpuid_vendor.ecx, 4);
  vendor[12] = 0;
  if (strcmp(vendor, "GenuineIntel") && strcmp(vendor, "AuthenticAMD")) {
    CLEAN_FATAL() << "Unknown CPU vendor '" << vendor << "'";
  }

  auto cpuid_data = cpuid(CPUID_GETFEATURES, 0);
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
    case 0x306C0:
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
    case 0x50670:
      return IntelSilvermont;
    case 0x806e0:
    case 0x906e0:
      return IntelKabylake;
    case 0x00f10:
      if (ext_family == 8) {
        if (!Flags::get().suppress_environment_warnings) {
          fprintf(stderr, "You have a Ryzen CPU. The Ryzen "
                          "retired-conditional-branches hardware\n"
                          "performance counter is not accurate enough; rr will "
                          "be unreliable.\n"
                          "See https://github.com/mozilla/rr/issues/2034.\n");
        }
        return AMDRyzen;
      }
      break;
    default:
      break;
  }

  if (!strcmp(vendor, "AuthenticAMD")) {
    CLEAN_FATAL()
        << "AMD CPUs not supported.\n"
        << "For Ryzen, see https://github.com/mozilla/rr/issues/2034.\n"
        << "For post-Ryzen CPUs, please file a Github issue.";
  } else {
    CLEAN_FATAL() << "Intel CPU type " << HEX(cpu_type) << " unknown";
  }
  return UnknownCpu; // not reached
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
  int fd = syscall(__NR_perf_event_open, attr, tid, -1, group_fd, 0);
  if (0 > fd && errno == EINVAL && attr->type == PERF_TYPE_RAW &&
      (attr->config & IN_TXCP)) {
    // The kernel might not support IN_TXCP, so try again without it.
    struct perf_event_attr tmp_attr = *attr;
    tmp_attr.config &= ~IN_TXCP;
    fd = syscall(__NR_perf_event_open, &tmp_attr, tid, -1, group_fd, 0);
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
  if (0 > fd) {
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

volatile int accumulator_sink = 0;

static void do_branches() {
  // Do NUM_BRANCHES conditional branches that can't be optimized out.
  // 'accumulator' is always odd and can't be zero
  int accumulator = rand() * 2 + 1;
  for (int i = 0; i < NUM_BRANCHES && accumulator; ++i) {
    accumulator = ((accumulator * 7) + 2) & 0xffffff;
  }
  // Use 'accumulator' so it can't be  optimized out.
  accumulator_sink = accumulator;
}

static void check_for_kvm_in_txcp_bug() {
  int64_t count = 0;
  struct perf_event_attr attr = rr::ticks_attr;
  attr.config |= IN_TXCP;
  attr.sample_period = 0;
  bool disabled_txcp;
  ScopedFd fd = start_counter(0, -1, &attr, &disabled_txcp);
  if (fd.is_open() && !disabled_txcp) {
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    do_branches();
    count = read_counter(fd);
  }

  supports_txcp = count > 0;
  has_kvm_in_txcp_bug = supports_txcp && count < NUM_BRANCHES;
  LOG(debug) << "supports txcp=" << supports_txcp;
  LOG(debug) << "has_kvm_in_txcp_bug=" << has_kvm_in_txcp_bug
             << " count=" << count;
}

static void check_for_xen_pmi_bug() {
  int32_t count = -1;
  struct perf_event_attr attr = rr::ticks_attr;
  attr.sample_period = NUM_BRANCHES - 1;
  ScopedFd fd = start_counter(0, -1, &attr);
  if (fd.is_open()) {
    // Do NUM_BRANCHES conditional branches that can't be optimized out.
    // 'accumulator' is always odd and can't be zero
    uint32_t accumulator = rand() * 2 + 1;
    int raw_fd = fd;
    asm volatile(
#if defined(__x86_64__)
        "mov %[_SYS_ioctl], %%rax;"
        "mov %[raw_fd], %%edi;"
        "xor %%rdx, %%rdx;"
        "mov %[_PERF_EVENT_IOC_ENABLE], %%rsi;"
        "syscall;"
        "cmp $-4095, %%rax;"
        "jae 2f;"
        "mov %[_SYS_ioctl], %%rax;"
        "mov %[_PERF_EVENT_IOC_RESET], %%rsi;"
        "syscall;"
        // From this point on all conditional branches count!
        "cmp $-4095, %%rax;"
        "jae 2f;"
        // Reset the counter period to the desired value.
        "mov %[_SYS_ioctl], %%rax;"
        "mov %[_PERF_EVENT_IOC_PERIOD], %%rsi;"
        "mov %[period], %%rdx;"
        "syscall;"
        "cmp $-4095, %%rax;"
        "jae 2f;"
        "mov %[_iterations], %%rax;"
        "1: dec %%rax;"
        // Multiply by 7.
        "mov %[accumulator], %%edx;"
        "shl $3, %[accumulator];"
        "sub %%edx, %[accumulator];"
        // Add 2.
        "add $2, %[accumulator];"
        // Mask off bits.
        "and $0xffffff, %[accumulator];"
        // And loop.
        "test %%rax, %%rax;"
        "jnz 1b;"
        "mov %[_PERF_EVENT_IOC_DISABLE], %%rsi;"
        "mov %[_SYS_ioctl], %%rax;"
        "xor %%rdx, %%rdx;"
        // We didn't touch rdi.
        "syscall;"
        "cmp $-4095, %%rax;"
        "jae 2f;"
        "movl $0, %[count];"
        "2: nop;"
#elif defined(__i386__)
        "mov %[_SYS_ioctl], %%eax;"
        "mov %[raw_fd], %%ebx;"
        "xor %%edx, %%edx;"
        "mov %[_PERF_EVENT_IOC_ENABLE], %%ecx;"
        "int $0x80;"
        "cmp $-4095, %%eax;"
        "jae 2f;"
        "mov %[_SYS_ioctl], %%eax;"
        "mov %[_PERF_EVENT_IOC_RESET], %%ecx;"
        "int $0x80;"
        // From this point on all conditional branches count!
        "cmp $-4095, %%eax;"
        "jae 2f;"
        // Reset the counter period to the desired value.
        "mov %[_SYS_ioctl], %%eax;"
        "mov %[_PERF_EVENT_IOC_PERIOD], %%ecx;"
        "mov %[period], %%edx;"
        "int $0x80;"
        "cmp $-4095, %%eax;"
        "jae 2f;"
        "mov %[_iterations], %%eax;"
        "1: dec %%eax;"
        // Multiply by 7.
        "mov %[accumulator], %%edx;"
        "shll $3, %[accumulator];"
        "sub %%edx, %[accumulator];"
        // Add 2.
        "add $2, %[accumulator];"
        // Mask off bits.
        "andl $0xffffff, %[accumulator];"
        // And loop.
        "test %%eax, %%eax;"
        "jnz 1b;"
        "mov %[_PERF_EVENT_IOC_DISABLE], %%ecx;"
        "mov %[_SYS_ioctl], %%eax;"
        "xor %%edx, %%edx;"
        // We didn't touch rdi.
        "int $0x80;"
        "cmp $-4095, %%eax;"
        "jae 2f;"
        "movl $0, %[count];"
        "2: nop;"
#else
#error unknown CPU architecture
#endif
        : [accumulator] "+rm"(accumulator), [count] "=rm"(count)
        : [_SYS_ioctl] "i"(SYS_ioctl),
          [_PERF_EVENT_IOC_DISABLE] "i"(PERF_EVENT_IOC_DISABLE),
          [_PERF_EVENT_IOC_ENABLE] "i"(PERF_EVENT_IOC_ENABLE),
          [_PERF_EVENT_IOC_PERIOD] "i"(PERF_EVENT_IOC_PERIOD),
          [_PERF_EVENT_IOC_RESET] "i"(PERF_EVENT_IOC_RESET),
          // The check for the failure of some of our ioctls is in
          // the measured region, so account for that when looping.
          [_iterations] "i"(NUM_BRANCHES - 2),
          [period] "rm"(&attr.sample_period), [raw_fd] "rm"(raw_fd)
        :
#if defined(__x86_64__)
        "rax", "rdx", "rdi", "rsi"
        // `syscall` clobbers rcx and r11.
        ,
        "rcx", "r11"
#elif defined(__i386__)
        "eax", "ebx", "ecx", "edx"
#else
#error unknown CPU architecture
#endif
        );
    // If things worked above, `count` should have been set to 0.
    if (count == 0) {
      count = read_counter(fd);
    }
    // Use 'accumulator' so it can't be optimized out.
    accumulator_sink = accumulator;
  }

  has_xen_pmi_bug = count > NUM_BRANCHES || count == -1;
  if (has_xen_pmi_bug) {
    LOG(debug) << "has_xen_pmi_bug=" << has_xen_pmi_bug << " count=" << count;
    if (!Flags::get().force_things) {
      FATAL()
          << "Overcount triggered by PMU interrupts detected due to Xen PMU "
             "virtualization bug.\n"
             "Aborting. Retry with -F to override, but it will probably\n"
             "fail.";
    }
  }
}

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

  if (only_one_counter &&
      (cpuid(CPUID_GETEXTENDEDFEATURES, 0).ebx & HLE_FEATURE_FLAG) &&
      !Flags::get().suppress_environment_warnings) {
    fprintf(stderr,
            "Your CPU supports Hardware Lock Elision but you only have one\n"
            "hardware performance counter available. Record and replay\n"
            "of code that uses HLE will fail unless you alter your\n"
            "configuration to make more than one hardware performance counter\n"
            "available.\n");
  }
}

static void check_for_bugs() {
  if (running_under_rr()) {
    // Under rr we emulate idealized performance counters, so we can assume
    // none of the bugs apply.
    return;
  }

  check_for_ioc_period_bug();
  check_for_kvm_in_txcp_bug();
  check_for_xen_pmi_bug();
  check_working_counters();
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

  if (!pmu->supported) {
    FATAL() << "Microarchitecture `" << pmu->name << "' currently unsupported.";
  }

  skid_size = pmu->skid_size;
  init_perf_event_attr(&ticks_attr, PERF_TYPE_RAW, pmu->rcb_cntr_event);
  init_perf_event_attr(&cycles_attr, PERF_TYPE_HARDWARE,
                       PERF_COUNT_HW_CPU_CYCLES);
  init_perf_event_attr(&hw_interrupts_attr, PERF_TYPE_RAW,
                       pmu->hw_intr_cntr_event);
  // libpfm encodes the event with this bit set, so we'll do the
  // same thing.  Unclear if necessary.
  hw_interrupts_attr.exclude_hv = 1;

  check_for_bugs();
  /*
   * For maintainability, and since it doesn't impact performance when not
   * needed, we always activate this. If it ever turns out to be a problem,
   * this can be set to pmu->benefits_from_useless_counter, instead.
   *
   * We also disable this counter when running under rr. Even though it's the
   * same event for the same task as the outer rr, the linux kernel does not
   * coalesce them and tries to schedule the new one on a general purpose PMC.
   * On CPUs with only 2 general PMCs (e.g. KNL), we'd run out.
   */
  activate_useless_counter = has_ioc_period_bug && !running_under_rr();
}

bool PerfCounters::is_ticks_attr(const perf_event_attr& attr) {
  init_attributes();
  perf_event_attr tmp_attr = attr;
  tmp_attr.sample_period = 0;
  tmp_attr.config &= ~IN_TXCP;
  return memcmp(&ticks_attr, &tmp_attr, sizeof(attr)) == 0;
}

uint32_t PerfCounters::skid_size() {
  init_attributes();
  return rr::skid_size;
}

PerfCounters::PerfCounters(pid_t tid)
    : tid(tid), started(false), counting(false) {
  init_attributes();
}

static void make_counter_async(ScopedFd& fd, int signal) {
  if (fcntl(fd, F_SETFL, O_ASYNC) || fcntl(fd, F_SETSIG, signal)) {
    FATAL() << "Failed to make ticks counter ASYNC with sig"
            << signal_name(signal);
  }
}

static bool always_recreate_counters() {
  // When we have the KVM IN_TXCP bug, reenabling the TXCP counter after
  // disabling it does not work.
  return has_ioc_period_bug || has_kvm_in_txcp_bug;
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
    attr.sample_period = ticks_period;
    fd_ticks_interrupt = start_counter(tid, -1, &attr);

    if (!only_one_counter && supports_txcp) {
      if (has_kvm_in_txcp_bug) {
        // IN_TXCP isn't going to work reliably. Assume that HLE/RTM are not
        // used,
        // and check that.
        attr.sample_period = 0;
        attr.config |= IN_TX;
        fd_ticks_in_transaction = start_counter(tid, fd_ticks_interrupt, &attr);
      } else {
        // Set up a separate counter for measuring ticks, which does not have
        // a sample period and does not count events during aborted
        // transactions.
        // We have to use two separate counters here because the kernel does
        // not support setting a sample_period with IN_TXCP, apparently for
        // reasons related to this Intel note on IA32_PERFEVTSEL2:
        // ``When IN_TXCP=1 & IN_TX=1 and in sampling, spurious PMI may
        // occur and transactions may continuously abort near overflow
        // conditions. Software should favor using IN_TXCP for counting over
        // sampling. If sampling, software should use large “sample-after“
        // value after clearing the counter configured to use IN_TXCP and
        // also always reset the counter even when no overflow condition
        // was reported.''
        attr.sample_period = 0;
        attr.config |= IN_TXCP;
        fd_ticks_measure = start_counter(tid, fd_ticks_interrupt, &attr);
      }
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
    if (fd_ticks_measure.is_open()) {
      ioctl(fd_ticks_measure, PERF_EVENT_IOC_DISABLE, 0);
    }
    if (fd_ticks_in_transaction.is_open()) {
      ioctl(fd_ticks_in_transaction, PERF_EVENT_IOC_DISABLE, 0);
    }
  }
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

  uint64_t adjusted_counting_period =
      counting_period +
      (t->session().is_recording() ? recording_skid_size() : skid_size());
  uint64_t interrupt_val = read_counter(fd_ticks_interrupt);
  if (!fd_ticks_measure.is_open()) {
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
