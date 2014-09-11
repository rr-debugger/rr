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

class TraceIfstream;
class TraceOfstream;

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
  typedef uint32_t Time;

  TraceFrame(Time global_time, pid_t tid, EncodedEvent event) {
    basic_info.global_time = global_time;
    basic_info.tid = tid;
    basic_info.ev = event;
    exec_info.ticks = 0;
  }
  TraceFrame() {
    basic_info.global_time = 0;
    basic_info.tid = 0;
    basic_info.ev.encoded = 0;
    exec_info.ticks = 0;
  }

  void set_exec_info(Ticks ticks, const Registers& regs,
                     const PerfCounters::Extra* extra_perf_values,
                     const ExtraRegisters* extra_regs);

  Time time() const { return basic_info.global_time; }
  pid_t tid() const { return basic_info.tid; }
  EncodedEvent event() const { return basic_info.ev; }

  Ticks ticks() const { return exec_info.ticks; }
  const Registers& regs() const { return exec_info.recorded_regs; }
  const ExtraRegisters& extra_regs() const { return recorded_extra_regs; }

  /**
   * Log a human-readable representation of this to |out|
   * (defaulting to stdout), including a newline character.  An
   * easily machine-parseable format is dumped when |raw_dump|
   * is true, otherwise a human-friendly format is used.
   * Does not emit a trailing '}' (so the caller can add more fields
   * to the record.
   */
  void dump(FILE* out = nullptr, bool raw_dump = false);

  friend TraceIfstream& operator>>(TraceIfstream& tif, TraceFrame& frame);
  friend TraceOfstream& operator<<(TraceOfstream& tif, const TraceFrame& frame);

private:
  struct {
    Time global_time;
    pid_t tid;
    EncodedEvent ev;
  } basic_info;

  struct {
    Ticks ticks;
    PerfCounters::Extra extra_perf_values;
    Registers recorded_regs;
  } exec_info;

  // Only used when has_exec_info, but variable length (and usually not
  // present) so we don't want to stuff it into exec_info
  ExtraRegisters recorded_extra_regs;
};

#endif /* RR_TRACE_FRAME_H_ */
