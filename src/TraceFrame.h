/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_FRAME_H_
#define RR_TRACE_FRAME_H_

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "Event.h"
#include "ExtraRegisters.h"
#include "PerfCounters.h"
#include "Registers.h"
#include "Ticks.h"

namespace rr {

class TraceReader;
class TraceWriter;

typedef int64_t FrameTime;

/**
 * A trace_frame is one "trace event" from a complete trace.  During
 * recording, a trace_frame is recorded upon each significant event,
 * for example a context-switch or syscall.  During replay, a
 * trace_frame represents a "next state" that needs to be transitioned
 * into, and the information recorded in the frame dictates the nature
 * of the transition.
 */
class TraceFrame {
public:
  TraceFrame(FrameTime global_time, pid_t tid, const Event& event,
             Ticks tick_count, double monotonic_time = 0);
  TraceFrame() : global_time(0), tid_(0), ticks_(0), monotonic_time_(0) {}

  FrameTime time() const { return global_time; }
  pid_t tid() const { return tid_; }
  const Event& event() const { return ev; }
  Ticks ticks() const { return ticks_; }
  double monotonic_time() const { return monotonic_time_; }

  const Registers& regs() const { return recorded_regs; }
  const ExtraRegisters& extra_regs() const { return recorded_extra_regs; }

  /**
   * Log a human-readable representation of this to |out|
   * (defaulting to stdout), including a newline character.
   * A human-friendly format is used. Does not emit a trailing '}'
   * (so the caller can add more fields to the record).
   */
  void dump(FILE* out = nullptr) const;
  /**
   * Log a human-readable representation of this to |out|
   * (defaulting to stdout), including a newline character.  An
   * easily machine-parseable format is dumped.
   */
  void dump_raw(FILE* out = nullptr) const;

private:
  friend class TraceReader;
  friend class TraceWriter;

  FrameTime global_time;
  pid_t tid_;
  Event ev;
  Ticks ticks_;
  double monotonic_time_;

  Registers recorded_regs;

  // Only used when has_exec_info, but variable length (and usually not
  // present) so we don't want to stuff it into exec_info
  ExtraRegisters recorded_extra_regs;
};

} // namespace rr

#endif /* RR_TRACE_FRAME_H_ */
