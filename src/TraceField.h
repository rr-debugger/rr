/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACE_FIELD_H_
#define RR_TRACE_FIELD_H_

#include <string>
#include <vector>

#include "core.h"

namespace rr {

enum TraceFieldKind {
  TRACE_EVENT_NUMBER,      // outputs 64-bit value
  TRACE_INSTRUCTION_COUNT, // outputs 64-bit value
  TRACE_IP,                // outputs 64-bit value
  TRACE_FSBASE,            // outputs 64-bit value
  TRACE_GSBASE,            // outputs 64-bit value
  TRACE_FLAGS,             // outputs 64-bit value
  TRACE_ORIG_AX,           // outputs 64-bit value
  TRACE_SEG_REG,           // outputs 64-bit value
  TRACE_XINUSE,            // outputs 64-bit value
  TRACE_GP_REG,            // outputs 64-bit value
  TRACE_XMM_REG,           // outputs 128-bit value
  TRACE_YMM_REG,           // outputs 256-bit value
  TRACE_FIP,               // outputs 64-bit value
  TRACE_FOP,               // outputs 16-bit value
  TRACE_TID,               // outputs 32-bit value
  TRACE_MXCSR,             // outputs 32-bit value
  TRACE_TICKS,             // outputs 64-bit value
};
struct TraceField {
  TraceFieldKind kind;
  uint8_t reg_num;
};

void print_trace_fields(ReplayTask* t, FrameTime event, uint64_t instruction_count,
                        bool raw, const std::vector<TraceField>& fields, FILE* out);

bool parse_trace_fields(const std::string& value, std::vector<TraceField>* out);

} // namespace rr

#endif /* RR_TRACE_FIELD_H_ */
