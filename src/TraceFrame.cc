/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "TraceFrame"

#include "TraceFrame.h"

#include <assert.h>
#include <inttypes.h>

void TraceFrame::set_exec_info(Ticks ticks, const Registers& regs,
                               const PerfCounters::Extra* extra_perf_values,
                               const ExtraRegisters* extra_regs) {
  assert(event().has_exec_info == HAS_EXEC_INFO);
  exec_info.ticks = ticks;
  exec_info.recorded_regs = regs;
  if (extra_perf_values) {
    exec_info.extra_perf_values = *extra_perf_values;
  }
  if (extra_regs) {
    recorded_extra_regs = *extra_regs;
  }
}

void TraceFrame::dump(FILE* out) const {
  out = out ? out : stdout;

  fprintf(out, "{\n  global_time:%u, event:`%s' (state:%d), tid:%d", time(),
          Event(event()).str().c_str(), event().state, tid());
  if (!event().has_exec_info) {
    fprintf(out, "\n");
    return;
  }

  if (PerfCounters::extra_perf_counters_enabled()) {
    fprintf(out, "\n  hw_ints:%lld faults:%lld rbc:%" PRId64 " insns:%lld\n",
            exec_info.extra_perf_values.hw_interrupts,
            exec_info.extra_perf_values.page_faults, ticks(),
            exec_info.extra_perf_values.instructions_retired);
  } else {
    fprintf(out, "\n  rbc:%" PRId64 "\n", ticks());
  }
  regs().print_register_file_for_trace(out);
}

void TraceFrame::dump_raw(FILE* out) const {
  out = out ? out : stdout;

  fprintf(out, " %d %d %d", time(), tid(), event().encoded);
  if (!event().has_exec_info) {
    fprintf(out, "\n");
    return;
  }

  fprintf(out, " %lld %lld %" PRId64 " %lld",
          exec_info.extra_perf_values.hw_interrupts,
          exec_info.extra_perf_values.page_faults, ticks(),
          exec_info.extra_perf_values.instructions_retired);
  regs().print_register_file_for_trace_raw(out);
  fprintf(out, "\n");
}
