/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
// This file is included from PerfCounters.cc

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
static std::ostream &operator<<(std::ostream &stm, const CPUID &cpuid)
{
  stm << std::hex << "implementer: 0x" << int(cpuid.implementer)
      << ", variant: 0x" << int(cpuid.variant) << " part: 0x" << int(cpuid.part);
  return stm;
}

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
    case 0xd41:
      return ARMCortexA78;
    case 0xd44:
      return ARMCortexX1;
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
      return AppleM1Icestorm;
    case 0x23:
      return AppleM1Firestorm;
    }
    break;
  }
  CLEAN_FATAL() << "Unknown aarch64 CPU type " << cpuid;
  return UnknownCpu; // not reached
}

static void set_cpuid(std::vector<CPUID> &cpuids, unsigned long cpuidx, CPUID cpuid)
{
  if (cpuids.size() <= cpuidx) {
    cpuids.resize(cpuidx + 1);
  }
  if (cpuids[cpuidx]) {
    CLEAN_FATAL() << "Duplicated CPUID for core " << cpuidx;
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
      CLEAN_FATAL() << "Failed to read midr register from kernel";
    }
    uint64_t val = 0;
    file >> std::hex >> val;
    if (!file) {
      CLEAN_FATAL() << "Failed to read midr register from kernel";
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
    LOG(warn) << "Unable to read CPU type from sysfs, trying procfs instead.";
    get_cpuinfo_procfs(cpuids);
  }
  if (cpuids.empty()) {
    CLEAN_FATAL() << "Failed to read midr register from kernel";
  }
  for (auto &cpuid : cpuids) {
    if (!cpuid) {
      CLEAN_FATAL() << "Unable to find CPU id for core " << &cpuid - &cpuids[0];
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

static void arch_check_restricted_counter() {
  if (!Flags::get().suppress_environment_warnings) {
    fprintf(stderr,
            "Your CPU supports only one performance counter.\n"
            "Use of LL/SC instructions will not be detected and will\n"
            "cause silently corrupt recordings. It is highly recommended\n"
            "that you alter your configuration to enable additional performance\n"
            "counters.\n");
  }
}

static bool always_recreate_counters(__attribute__((unused)) const perf_event_attrs &perf_attr) {
  return false;
}

static void check_for_arch_bugs(__attribute__((unused)) perf_event_attrs &perf_attr) {}

static void post_init_pmu_uarchs(std::vector<PmuConfig> &pmu_uarchs)
{
  std::map<std::string,int> pmu_types;
  size_t npmus = pmu_uarchs.size();
  int pmu_type_failed = 0;
  auto fallback_pmu = [] (PmuConfig &pmu_uarch) {
    pmu_uarch.pmu_name = nullptr;
    if (pmu_uarch.cycle_type != PERF_TYPE_HARDWARE) {
      pmu_uarch.cycle_type = PERF_TYPE_HARDWARE;
      pmu_uarch.cycle_event = PERF_COUNT_HW_CPU_CYCLES;
    }
    if (pmu_uarch.event_type != PERF_TYPE_RAW) {
      pmu_uarch.event_type = PERF_TYPE_RAW;
    }
  };
  auto set_pmu_type = [] (PmuConfig &pmu_uarch, int type) {
    if (pmu_uarch.cycle_type != PERF_TYPE_HARDWARE) {
      pmu_uarch.cycle_type = type;
    }
    if (pmu_uarch.event_type != PERF_TYPE_RAW) {
      pmu_uarch.event_type = type;
    }
  };
  bool has_unknown = false;
  for (size_t i = 0; i < npmus; i++) {
    auto &pmu_uarch = pmu_uarchs[i];
    if (!(pmu_uarch.flags & (PMU_TICKS_RCB | PMU_TICKS_TAKEN_BRANCHES))) {
      has_unknown = true;
      continue;
    }
    if (!pmu_uarch.pmu_name) {
      CLEAN_FATAL() << "Unknown PMU name for core " << i;
      continue;
    }
    std::string pmu_name(pmu_uarch.pmu_name);
    auto &pmu_type = pmu_types[pmu_name];
    if (pmu_type == -1) {
      fallback_pmu(pmu_uarch);
      continue;
    }
    if (pmu_type) {
      set_pmu_type(pmu_uarch, pmu_type);
      continue;
    }
    auto filename = "/sys/bus/event_source/devices/" + pmu_name + "/type";
    std::ifstream file(filename);
    int val = 0;
    bool failed = false;
    if (!file) {
      failed = true;
      LOG(warn) << "Cannot open " << filename;
    }
    else {
      file >> val;
      if (!file) {
        failed = true;
        LOG(warn) << "Cannot read " << filename;
      }
    }
    if (failed) {
      // Record the failure and fallback to the kernel raw and hardware events instead
      pmu_type_failed++;
      fallback_pmu(pmu_uarch);
      pmu_type = -1;
    }
    else {
      set_pmu_type(pmu_uarch, val);
      pmu_type = val;
    }
  }
  if (pmu_types.size() == 1 && !has_unknown) {
    bool single_type = true;
    auto &pmu_uarch0 = pmu_uarchs[0];
    // Apparently the same PMU type doesn't actually mean the same PMU events...
    for (auto &pmu_uarch: pmu_uarchs) {
      if (&pmu_uarch == &pmu_uarch0) {
        // Skip first
        continue;
      }
      if (pmu_uarch.rcb_cntr_event != pmu_uarch0.rcb_cntr_event ||
          pmu_uarch.minus_ticks_cntr_event != pmu_uarch0.minus_ticks_cntr_event ||
          pmu_uarch.llsc_cntr_event != pmu_uarch0.llsc_cntr_event) {
        single_type = false;
        break;
      }
    }
    if (single_type) {
      // Single PMU type
      pmu_uarchs.resize(1);
    }
  }
  if (pmu_uarchs.size() != 0 && pmu_type_failed) {
    // If reading PMU type failed, we only allow a single PMU type to be sure
    // that we get what we want from the kernel events.
    CLEAN_FATAL() << "Unable to read PMU event types";
  }
}

template <>
void PerfCounters::reset_arch_extras<ARM64Arch>() {
  // LL/SC can't be recorded reliably. Start a counter to detect
  // any usage, such that we can give an intelligent error message.
  struct perf_event_attr attr = perf_attrs[pmu_index].llsc_fail;
  attr.sample_period = 0;
  fd_strex_counter = start_counter(tid, fd_ticks_interrupt, &attr);
}
