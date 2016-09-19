/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "TraceFrame.h"

#include <assert.h>
#include <inttypes.h>

#include "util.h"

namespace rr {

TraceFrame::TraceFrame(Time global_time, pid_t tid, const Event& event,
                       Ticks tick_count, double monotonic_time)
    : global_time(global_time),
      tid_(tid),
      ev(event),
      ticks_(tick_count),
      monotonic_time_(monotonic_time ? monotonic_time : monotonic_now_sec()) {}

void TraceFrame::set_exec_info(const Registers& regs,
                               const PerfCounters::Extra* extra_perf_values,
                               const ExtraRegisters* extra_regs) {
  assert(event().record_exec_info() == HAS_EXEC_INFO);
  recorded_regs = regs;
  if (extra_perf_values) {
    extra_perf = *extra_perf_values;
  }
  if (extra_regs) {
    recorded_extra_regs = *extra_regs;
  }
}

void TraceFrame::dump(FILE* out) const {
  out = out ? out : stdout;

  fprintf(out, "{\n  real_time:%f global_time:%u, event:`%s' ",
          monotonic_time(), time(), event().str().c_str());
  if (event().is_syscall_event()) {
    fprintf(out, "(state:%s) ", state_name(event().Syscall().state));
  }
  fprintf(out, "tid:%d, ticks:%" PRId64 "\n", tid(), ticks());
  if (event().has_exec_info() != HAS_EXEC_INFO) {
    return;
  }

  if (PerfCounters::extra_perf_counters_enabled()) {
    fprintf(out, "  hw_ints:%" PRId64 " faults:%" PRId64 " insns:%" PRId64 "\n",
            extra_perf.hw_interrupts, extra_perf.page_faults,
            extra_perf.instructions_retired);
  }
  regs().print_register_file_compact(out);
  if (recorded_extra_regs.format() != ExtraRegisters::NONE) {
    fputc(' ', out);
    recorded_extra_regs.print_register_file_compact(out);
  }
  fprintf(out, "\n");
}

void TraceFrame::dump_raw(FILE* out) const {
  out = out ? out : stdout;

  fprintf(out, " %d %d %d %" PRId64, time(), tid(), event().encode().encoded,
          ticks());
  if (event().has_exec_info() != HAS_EXEC_INFO) {
    fprintf(out, "\n");
    return;
  }

  fprintf(out, " %" PRId64 " %" PRId64 " %" PRId64, extra_perf.hw_interrupts,
          extra_perf.page_faults, extra_perf.instructions_retired);
  regs().print_register_file_for_trace_raw(out);
  fprintf(out, "\n");
}

} // namespace rr
