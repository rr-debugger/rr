/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "replayer.h"

#include <assert.h>

#include <limits>
#include <string>


using namespace rr;
using namespace std;

// Setting these causes us to trace instructions after
// instruction_trace_at_event_start up to and including
// instruction_trace_at_event_last
static TraceFrame::Time instruction_trace_at_event_start = 0;
static TraceFrame::Time instruction_trace_at_event_last = 0;

bool trace_instructions_up_to_event(TraceFrame::Time event) {
  return event > instruction_trace_at_event_start &&
         event <= instruction_trace_at_event_last;
}
