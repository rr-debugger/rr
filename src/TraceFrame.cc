/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "TraceFrame.h"

#include <inttypes.h>

#include "core.h"
#include "util.h"

namespace rr {

TraceFrame::TraceFrame(FrameTime global_time, pid_t tid, const Event& event,
                       Ticks tick_count, double monotonic_time)
    : global_time(global_time),
      tid_(tid),
      ev(event),
      ticks_(tick_count),
      monotonic_time_(monotonic_time ? monotonic_time : monotonic_now_sec()) {}

void TraceFrame::dump(FILE* out) const {
  out = out ? out : stdout;

  fprintf(out, "{\n  real_time:%f global_time:%llu, event:`%s' ",
          monotonic_time(), (long long)time(), event().str().c_str());
  if (event().is_syscall_event()) {
    fprintf(out, "(state:%s) ", state_name(event().Syscall().state));
  }
  fprintf(out, "tid:%d, ticks:%" PRId64 "\n", tid(), ticks());
  if (!event().record_regs()) {
    return;
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

  fprintf(out, " %lld %d %d %" PRId64, (long long)time(), tid(), event().type(),
          ticks());
  if (!event().record_regs()) {
    fprintf(out, "\n");
    return;
  }

  regs().print_register_file_for_trace_raw(out);
  fprintf(out, "\n");
}

} // namespace rr
