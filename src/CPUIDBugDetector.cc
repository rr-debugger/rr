/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "CPUIDBugDetector.h"
#include "Event.h"
#include "Flags.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "kernel_abi.h"

extern "C" int cpuid_loop(int iterations);

using namespace std;

namespace rr {

void CPUIDBugDetector::run_detection_code() {
  // Call cpuid_loop to generate trace data we can use to detect
  // the cpuid rcb undercount bug. This generates 4 geteuid
  // calls which should have 2 rcbs between each of the
  // 3 consecutive pairs.
  cpuid_loop(4);
}

static bool rcb_counts_ok(uint64_t prev, uint64_t current) {
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
        "    counter. Work around this problem by adding\n"
        "        monitor_control.disable_hvsim_clusters = true\n"
        "    to your .vmx file.\n"
        "\n");
  }
  return false;
}

void CPUIDBugDetector::notify_reached_syscall_during_replay(ReplayTask* t) {
  // We only care about events that happen before the first exec,
  // when our detection code runs.
  if (t->session().done_initial_exec()) {
    return;
  }
  const Event& ev = t->current_trace_frame().event();
  if (!is_geteuid32_syscall(ev.Syscall().number, t->arch()) &&
      !is_geteuid_syscall(ev.Syscall().number, t->arch())) {
    return;
  }
  uint64_t trace_rcb_count = t->current_trace_frame().ticks();
  uint64_t actual_rcb_count = t->tick_count();
  if (trace_rcb_count_at_last_geteuid32 > 0 && !detected_cpuid_bug) {
    if (!rcb_counts_ok(trace_rcb_count_at_last_geteuid32, trace_rcb_count) ||
        !rcb_counts_ok(actual_rcb_count_at_last_geteuid32, actual_rcb_count)) {
      detected_cpuid_bug = true;
    }
  }
  trace_rcb_count_at_last_geteuid32 = trace_rcb_count;
  actual_rcb_count_at_last_geteuid32 = actual_rcb_count;
}

} // namespace rr
