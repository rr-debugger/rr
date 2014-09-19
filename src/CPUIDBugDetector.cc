/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "CPUIDBugDetector.h"
#include "Event.h"
#include "Flags.h"
#include "kernel_abi.h"
#include "session.h"
#include "task.h"

using namespace rr;

extern "C" int cpuid_loop(int iterations);

void CPUIDBugDetector::run_detection_code() {
  // Call cpuid_loop to generate trace data we can use to detect
  // the cpuid rbc undercount bug. This generates 4 geteuid
  // calls which should have 2 rbcs between each of the
  // 3 consecutive pairs.
  cpuid_loop(4);
}

static bool rbc_counts_ok(uint64_t prev, uint64_t current, const char* source) {
  if (current - prev == 2) {
    return true;
  }
  if (!Flags::get().suppress_environment_warnings) {
    fprintf(
        stderr,
        "\n"
        "rr: Warning: You appear to be running in a VMWare guest with a bug\n"
        "    where a conditional branch instruction between two CPUID "
        "instructions\n"
        "    sometimes fails to be counted by the conditional branch "
        "performance\n"
        "    counter. Partial workarounds have been enabled but replay may "
        "diverge.\n"
        "    Consider running rr not in a VMWare guest.\n"
        "\n");
  }
  return false;
}

void CPUIDBugDetector::notify_reached_syscall_during_replay(Task* t) {
  // We only care about events that happen before the first exec,
  // when our detection code runs.
  if (t->session().can_validate()) {
    return;
  }
  Event ev(t->current_trace_frame().event());
  if (!is_geteuid32_syscall(ev.Syscall().number, t->arch()) &&
      !is_geteuid_syscall(ev.Syscall().number, t->arch())) {
    return;
  }
  uint64_t trace_rbc_count = t->current_trace_frame().ticks();
  uint64_t actual_rbc_count = t->tick_count();
  if (trace_rbc_count_at_last_geteuid32 > 0 && !detected_cpuid_bug) {
    if (!rbc_counts_ok(trace_rbc_count_at_last_geteuid32, trace_rbc_count,
                       "trace") ||
        !rbc_counts_ok(actual_rbc_count_at_last_geteuid32, actual_rbc_count,
                       "actual")) {
      detected_cpuid_bug = true;
    }
  }
  trace_rbc_count_at_last_geteuid32 = trace_rbc_count;
  actual_rbc_count_at_last_geteuid32 = actual_rbc_count;
}
