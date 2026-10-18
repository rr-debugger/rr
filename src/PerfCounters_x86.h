/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
// This file is included from PerfCounters.cc

static bool has_kvm_in_txcp_bug;
static bool has_xen_pmi_bug;
static bool supports_txcp;

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
    CLEAN_FATAL() << "Unknown CPU vendor '" << vendor << "'";
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
    CLEAN_FATAL() << "AMD CPU family " << HEX(family) << " model " << HEX(model)
                  << " unknown";
  } else {
    CLEAN_FATAL() << "Intel CPU family " << HEX(family) << " model " << HEX(model)
                  << " unknown";
  }
  return UnknownCpu; // not reached
}

static vector<CPUInfo> compute_cpus_info() {
  vector<CPUInfo> result;
  auto groups = CPUs::get().cpu_groups();
  if (groups.empty()) {
    // Only one kind of CPU core.
    result.push_back({compute_cpu_microarch(), PERF_TYPE_RAW});
    return result;
  }

  for (int cpu : CPUs::get().initial_affinity()) {
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
    if (!CPUs::set_affinity_to_cpu(cpu)) {
      FATAL() << "Can't set affinity to previously allowed CPU";
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
            FATAL() << "Atom architecture detected but not known for " << uarch;
          }
        } else if (group.name == "lowpower") {
          switch (uarch) {
          case IntelArrowLake:
            uarch = IntelCrestmont;
            break;
          default:
            FATAL() << "Lowpower architecture detected but not known for " << uarch;
          }
        } else if (group.name != "core") {
          FATAL() << "Hybrid architecture group name not known: " << group.name;
        }
        for (int i = group.start_cpu; i < group.end_cpu; ++i) {
          result[i] = {uarch, group.type};
        }
        break;
      }
    }
  }
  CPUs::get().restore_initial_affinity();
  return result;
}

static void check_for_kvm_in_txcp_bug(const perf_event_attrs &perf_attr) {
  int64_t count = 0;
  struct perf_event_attr attr = perf_attr.ticks;
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

static void check_for_xen_pmi_bug(const perf_event_attrs &perf_attr) {
  int32_t count = -1;
  struct perf_event_attr attr = perf_attr.ticks;
  attr.sample_period = NUM_BRANCHES - 1;
  ScopedFd fd = start_counter(0, -1, &attr);
  if (fd.is_open()) {
    // Do NUM_BRANCHES conditional branches that can't be optimized out.
    // 'accumulator' is always odd and can't be zero
    uint32_t accumulator = uint32_t(rand()) * 2 + 1;
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
        "addl $2, %[accumulator];"
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
    } else {
      cpu_improperly_configured = true;
    }
  }
}

static void check_for_zen_speclockmap() {
  // When the SpecLockMap optimization is not disabled, rr will not work
  // reliably (e.g. it would work fine on a single process with a single
  // thread, but not more). When the optimization is disabled, the
  // perf counter for retired lock instructions of type SpecLockMapCommit
  // (on PMC 0x25) stays at 0.
  // See more details at https://github.com/rr-debugger/rr/issues/2034.
  struct perf_event_attr attr;
  // 0x25 == RETIRED_LOCK_INSTRUCTIONS - Counts the number of retired locked instructions
  // + 0x08 == SPECLOCKMAPCOMMIT
  init_perf_event_attr(&attr, PERF_TYPE_RAW, 0x510825);

  ScopedFd fd = start_counter(0, -1, &attr);
  if (fd.is_open()) {
    int atomic = 0;
    int64_t count = read_counter(fd);
    // A lock add is known to increase the perf counter we're looking at.
    asm volatile("lock addl $1, %0": "+m" (atomic));
    if (read_counter(fd) == count) {
      LOG(debug) << "SpecLockMap is disabled";
    } else {
      LOG(debug) << "SpecLockMap is not disabled";
      if (!Flags::get().force_things) {
        CLEAN_FATAL() <<
                "On Zen CPUs, rr will not work reliably unless you disable the "
                "hardware SpecLockMap optimization.\nFor instructions on how to "
                "do this, see https://github.com/rr-debugger/rr/wiki/Zen\n";
      } else {
        cpu_improperly_configured = true;
      }
    }
  }
}

static void check_for_freeze_on_smi() {
  ScopedFd fd = ScopedFd("/sys/devices/cpu/freeze_on_smi", O_RDONLY);
  if (!fd.is_open()) {
    LOG(debug) << "/sys/devices/cpu/freeze_on_smi not present";
    return;
  }

  char freeze_on_smi = 0;
  ssize_t ret = read(fd, &freeze_on_smi, 1);
  if (ret != 1) {
    FATAL() << "Can't read freeze_on_smi";
  }
  if (freeze_on_smi == 0) {
    LOG(warn) << "Failed to read freeze_on_smi";
  } else if (freeze_on_smi == '1') {
    LOG(debug) << "freeze_on_smi is set";
  } else if (freeze_on_smi == '0') {
    LOG(warn) << "freeze_on_smi is not set";
    if (!Flags::get().force_things) {
      CLEAN_FATAL() <<
              "Freezing performance counters on SMIs should be enabled for maximum rr\n"
              "reliability on Comet Lake and later CPUs. To manually enable this setting, run\n"
              "\techo 1 | sudo tee /sys/devices/cpu/freeze_on_smi\n"
              "On systemd systems, consider putting\n"
              "'w /sys/devices/cpu/freeze_on_smi - - - - 1' into /etc/tmpfiles.d/10-rr.conf\n"
              "to automatically apply this setting on every reboot.\n"
              "See 'man 5 sysfs', 'man 5 tmpfiles.d'.\n"
              "If you are seeing this message, the setting has not been enabled.\n";
    } else {
      cpu_improperly_configured = true;
    }
  } else {
    LOG(warn) << "Unrecognized freeze_on_smi value " << freeze_on_smi;
  }
}

// Must be run on the CPU where we're checking for bugs.
static void check_for_arch_bugs(perf_event_attrs &perf_attr) {
  CpuMicroarch uarch = (CpuMicroarch)perf_attr.bug_flags;
  if (uarch >= FirstIntel && uarch <= LastIntel) {
    check_for_kvm_in_txcp_bug(perf_attr);
    check_for_xen_pmi_bug(perf_attr);
  }
  if (uarch >= IntelCometLake && uarch <= LastIntel) {
    check_for_freeze_on_smi();
  }
  if (uarch >= AMDZen && uarch <= LastAMD) {
    check_for_zen_speclockmap();
  }
}

static void post_init_pmu_uarchs(std::vector<PmuConfig> &) {

}

static bool always_recreate_counters(const perf_event_attrs &perf_attr) {
  // When we have the KVM IN_TXCP bug, reenabling the TXCP counter after
  // disabling it does not work.
  DEBUG_ASSERT(perf_attr.checked);
  return perf_attr.has_ioc_period_bug || has_kvm_in_txcp_bug;
}

static void arch_check_restricted_counter() {
  if ((cpuid(CPUID_GETEXTENDEDFEATURES, 0).ebx & HLE_FEATURE_FLAG) &&
    !Flags::get().suppress_environment_warnings) {
    fprintf(stderr,
            "Your CPU supports Hardware Lock Elision but you only have one\n"
            "hardware performance counter available. Record and replay\n"
            "of code that uses HLE will fail unless you alter your\n"
            "configuration to make more than one hardware performance counter\n"
            "available.\n");
  }
}

template <typename Arch>
void PerfCounters::reset_arch_extras(int pmu_index) {
  if (supports_txcp) {
    struct perf_event_attr attr = rr::perf_attrs[pmu_index].ticks;
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
}
