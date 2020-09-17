/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
// This file is included from PerfCounters.cc

static const char* midr_path =
    "/sys/devices/system/cpu/cpu0/regs/identification/midr_el1";

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 */
static CpuMicroarch compute_cpu_microarch() {
  FILE *midr_el1 = fopen(midr_path, "r");
  if (!midr_el1) {
    CLEAN_FATAL() << "Failed to read midr register from kernel";
  }
  uint32_t midir;
  if (1 != fscanf(midr_el1, "%x", &midir)) {
    CLEAN_FATAL() << "Failed to read midr register from kernel";
  }
  fclose(midr_el1);
  switch (midir) {
    case 0x413fd0c1:
      return ARMNeoverseN1;
    default:
      break;
  }
  CLEAN_FATAL() << "Aarch64 CPU type " << HEX(midir) << " unknown";
  return UnknownCpu; // not reached
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

static bool always_recreate_counters() {
  return false;
}

static void check_for_arch_bugs(__attribute__((unused)) CpuMicroarch uarch) {}

template <>
void PerfCounters::reset_arch_extras<ARM64Arch>() {
  // LL/SC can't be recorded reliably. Start a counter to detect
  // any usage, such that we can give an intelligent error message.
  struct perf_event_attr attr = rr::llsc_fail_attr;
  attr.sample_period = 0;
  fd_strex_counter = start_counter(tid, fd_ticks_interrupt, &attr);
}
