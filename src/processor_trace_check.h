/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROCESSOR_TRACE_CHECK_H_
#define RR_PROCESSOR_TRACE_CHECK_H_

#include <ostream>

namespace rr {

class ReplayTask;

void check_intel_pt_if_enabled(ReplayTask* t);

void emergency_check_intel_pt(ReplayTask* t, std::ostream& stream);

} // namespace rr

#endif /* RR_PROCESSOR_TRACE_CHECK_H_ */
