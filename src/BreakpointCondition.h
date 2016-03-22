/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_BREAKPOINT_CONDITION_H_
#define RR_BREAKPOINT_CONDITION_H_

namespace rr {

class Task;

class BreakpointCondition {
public:
  virtual ~BreakpointCondition() {}
  virtual bool evaluate(Task* t) const = 0;
};

} // namespace rr

#endif // RR_BREAKPOINT_CONDITION_H_
