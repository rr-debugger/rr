/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
// This file is included from PerfCounters.cc

static bool has_kvm_in_txcp_bug;
static bool has_xen_pmi_bug;
static bool supports_txcp;

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
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
      return IntelGoldmont;
    case 0x706e0:
      return IntelIcelake;
    case 0x806e0:
    case 0x906e0:
      return IntelKabylake;
    case 0xa0650:
    case 0xa0660:
	return IntelCometlake;
    case 0x30f00:
      return AMDF15R30;
    case 0x00f10: // Naples, Whitehaven, Summit Ridge, Snowy Owl (Zen) (UNTESTED)
    case 0x10f10: // Raven Ridge, Great Horned Owl (Zen) (UNTESTED)
    case 0x10f80: // Banded Kestrel (Zen), Picasso (Zen+) (UNTESTED)
    case 0x20f00: // Dali (Zen) (UNTESTED)
    case 0x00f80: // Colfax, Pinnacle Ridge (Zen+) (UNTESTED)
    case 0x30f10: // Rome, Castle Peak (Zen 2)
    case 0x60f00: // Renoir (Zen 2) (UNTESTED)
    case 0x70f10: // Matisse (Zen 2) (UNTESTED)
      if (ext_family == 8) {
        return AMDZen;
      }
      break;
    default:
      break;
  }

  if (!strcmp(vendor, "AuthenticAMD")) {
    CLEAN_FATAL() << "AMD CPU type " << HEX(cpu_type) << " unknown";
  } else {
    CLEAN_FATAL() << "Intel CPU type " << HEX(cpu_type) << " unknown";
  }
  return UnknownCpu; // not reached
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
      fprintf(stderr,
              "On Zen CPUs, rr will not work reliably unless you disable the "
              "hardware SpecLockMap optimization.\nFor instructions on how to "
              "do this, see https://github.com/rr-debugger/rr/wiki/Zen\n");
    }
  }
}

static void check_for_arch_bugs(CpuMicroarch uarch) {
  if (uarch >= FirstIntel && uarch <= LastIntel) {
    check_for_kvm_in_txcp_bug();
    check_for_xen_pmi_bug();
  }
  if (uarch == AMDZen) {
    check_for_zen_speclockmap();
  }
}

static bool always_recreate_counters() {
  // When we have the KVM IN_TXCP bug, reenabling the TXCP counter after
  // disabling it does not work.
  return has_ioc_period_bug || has_kvm_in_txcp_bug;
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
void PerfCounters::reset_arch_extras() {
  if (supports_txcp) {
    struct perf_event_attr attr = rr::ticks_attr;
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
