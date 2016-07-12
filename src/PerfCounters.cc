/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "PerfCounters.h"

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

static bool attributes_initialized;
static struct perf_event_attr samples_attr;
static struct perf_event_attr ticks_attr;
static struct perf_event_attr page_faults_attr;
static struct perf_event_attr hw_interrupts_attr;
static struct perf_event_attr instructions_retired_attr;

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
  IntelSkylake
};

struct PmuConfig {
  CpuMicroarch uarch;
  const char* name;
  unsigned rcb_cntr_event;
  unsigned rinsn_cntr_event;
  unsigned hw_intr_cntr_event;
  bool supported;
};

// XXX please only edit this if you really know what you're doing.
static const PmuConfig pmu_configs[] = {
  { IntelSkylake, "Intel Skylake", 0x5101c4, 0x5100c0, 0x5301cb, true },
  { IntelBroadwell, "Intel Broadwell", 0x5101c4, 0x5100c0, 0x5301cb, true },
  { IntelHaswell, "Intel Haswell", 0x5101c4, 0x5100c0, 0x5301cb, true },
  { IntelIvyBridge, "Intel Ivy Bridge", 0x5101c4, 0x5100c0, 0x5301cb, true },
  { IntelSandyBridge, "Intel Sandy Bridge", 0x5101c4, 0x5100c0, 0x5301cb,
    true },
  { IntelNehalem, "Intel Nehalem", 0x5101c4, 0x5100c0, 0x50011d, true },
  { IntelWestmere, "Intel Westmere", 0x5101c4, 0x5100c0, 0x50011d, true },
  { IntelPenryn, "Intel Penryn", 0, 0, 0, false },
  { IntelMerom, "Intel Merom", 0, 0, 0, false },
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
    FATAL() << "Forced uarch " << Flags::get().forced_uarch << " isn't known.";
  }

  auto cpuid_data = cpuid(CPUID_GETFEATURES, 0);
  unsigned int cpu_type = (cpuid_data.eax & 0xF0FF0);
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
    case 0x406F0:
    case 0x50660:
      return IntelBroadwell;
    case 0x406e0:
    case 0x506e0:
      return IntelSkylake;
    default:
      FATAL() << "CPU " << HEX(cpu_type) << " unknown.";
      return UnknownCpu; // not reached
  }
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

static void check_sampling_limit() {
  static bool checked = false;
  if (checked)
    return;
  // Check perf event sample rate and print a helpful error message
  {
    char line[64];
    int fd = open("/proc/sys/kernel/perf_event_max_sample_rate", O_RDONLY);
    if (read(fd, line, sizeof(line)) > 0) {
      assert(atoi(line) >= 4000 &&
        "Make sure /proc/sys/kernel/perf_event_max_sample_rate is set high enough");
    }
    close(fd);
  }
}

static void init_samples_event() {
  memset(&rr::samples_attr, 0, sizeof(rr::samples_attr));
  rr::samples_attr.type = PERF_TYPE_HARDWARE;
  rr::samples_attr.size = sizeof(rr::samples_attr);
  rr::samples_attr.config = PERF_COUNT_HW_CPU_CYCLES;
  rr::samples_attr.sample_freq = 4000;
  rr::samples_attr.freq = 1;
  rr::samples_attr.sample_type = PERF_SAMPLE_IP|PERF_SAMPLE_TIME|PERF_SAMPLE_READ|PERF_SAMPLE_TID;
  rr::samples_attr.read_format = PERF_FORMAT_GROUP;
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
  assert(pmu);

  if (!pmu->supported) {
    FATAL() << "Microarchitecture `" << pmu->name << "' currently unsupported.";
  }

  init_perf_event_attr(&ticks_attr, PERF_TYPE_RAW, pmu->rcb_cntr_event);
  init_perf_event_attr(&instructions_retired_attr, PERF_TYPE_RAW,
                       pmu->rinsn_cntr_event);
  init_perf_event_attr(&hw_interrupts_attr, PERF_TYPE_RAW,
                       pmu->hw_intr_cntr_event);
  init_samples_event();
  // libpfm encodes the event with this bit set, so we'll do the
  // same thing.  Unclear if necessary.
  hw_interrupts_attr.exclude_hv = 1;
  init_perf_event_attr(&page_faults_attr, PERF_TYPE_SOFTWARE,
                       PERF_COUNT_SW_PAGE_FAULTS);
}

const struct perf_event_attr& PerfCounters::ticks_attr() {
  init_attributes();
  return rr::ticks_attr;
}

PerfCounters::PerfCounters(pid_t tid) : tid(tid), started(false),
    sampling_enabled(false) {
  init_attributes();
}

static ScopedFd start_counter(pid_t tid, int group_fd,
                              struct perf_event_attr* attr) {
  int fd = syscall(__NR_perf_event_open, attr, tid, -1, group_fd, 0);
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
  if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) {
    FATAL() << "Failed to start counter";
  }
  return fd;
}

static const int SAMPLE_MMAP_SIZE = (1+(1<<10))*PAGE_SIZE;
void PerfCounters::samples_unmapper::operator()(void *ptr)
{
 munmap(ptr, SAMPLE_MMAP_SIZE);
}

void PerfCounters::reset(Ticks ticks_period) {
  assert(ticks_period >= 0);

  if (!started) {
    int group_fd = -1;
    if (enable_sampling() && !samples_mmap) {
      check_sampling_limit();
      fd_samples = start_counter(tid, -1, &rr::samples_attr);
      samples_mmap.reset(mmap(NULL, SAMPLE_MMAP_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED, fd_samples, 0));
      if (samples_mmap.get() == MAP_FAILED) {
        FATAL() << "Failed to map samples page";
      }
      group_fd = fd_samples;
    }
    
    struct perf_event_attr attr = rr::ticks_attr;
    attr.sample_period = ticks_period;
    fd_ticks = start_counter(tid, group_fd, &attr);
    if (group_fd == -1)
      group_fd = fd_ticks;

    struct f_owner_ex own;
    own.type = F_OWNER_TID;
    own.pid = tid;
    if (fcntl(fd_ticks, F_SETOWN_EX, &own)) {
      FATAL() << "Failed to SETOWN_EX ticks event fd";
    }
    if (fcntl(fd_ticks, F_SETFL, O_ASYNC) ||
        fcntl(fd_ticks, F_SETSIG, PerfCounters::TIME_SLICE_SIGNAL)) {
      FATAL() << "Failed to make ticks counter ASYNC with sig"
              << signal_name(PerfCounters::TIME_SLICE_SIGNAL);
    }

    if (extra_perf_counters_enabled()) {
      fd_hw_interrupts = start_counter(tid, group_fd, &hw_interrupts_attr);
      fd_instructions_retired =
          start_counter(tid, group_fd, &instructions_retired_attr);
      fd_page_faults = start_counter(tid, group_fd, &page_faults_attr);
    }
  } else {
    ioctl(fd_ticks, PERF_EVENT_IOC_RESET);
    ioctl(fd_ticks, PERF_EVENT_IOC_PERIOD, &ticks_period);
  }
    
  started = true;
  counting = true;
}

void PerfCounters::stop() {
  if (!started) {
    return;
  }
  started = false;

  fd_ticks.close();
  fd_page_faults.close();
  fd_hw_interrupts.close();
  fd_instructions_retired.close();
}

static int64_t read_counter(ScopedFd& fd) {
  int64_t val;
  ssize_t nread = read(fd, &val, sizeof(val));
  assert(nread == sizeof(val));
  return val;
}

Ticks PerfCounters::read_ticks() {
  uint64_t period = UINT32_MAX;
  uint64_t val = started ? read_counter(fd_ticks) : 0;
  ioctl(fd_ticks, PERF_EVENT_IOC_RESET);
  ioctl(fd_ticks, PERF_EVENT_IOC_PERIOD, &period);
  return val;
}

PerfCounters::Extra PerfCounters::read_extra() {
  assert(extra_perf_counters_enabled());

  Extra extra;
  if (started) {
    extra.page_faults = read_counter(fd_page_faults);
    extra.hw_interrupts = read_counter(fd_hw_interrupts);
    extra.instructions_retired = read_counter(fd_instructions_retired);
  } else {
    memset(&extra, 0, sizeof(extra));
  }
  return extra;
}

} // namespace rr
