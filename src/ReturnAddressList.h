/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RETURNADDRESSLIST_H_
#define RR_RETURNADDRESSLIST_H_

#include <string.h>

#include "remote_ptr.h"

namespace rr {

class Task;

/**
 * A list of return addresses extracted from the stack. The tuple
 * (perfcounter ticks, regs, return addresses) may be needed to disambiguate
 * states that aren't unique in (perfcounter ticks, regs).
 * When return addresses can't be extracted, some suffix of the list may be
 * all zeroes.
 */
struct ReturnAddressList {
  enum { COUNT = 8 };
  remote_ptr<void> addresses[COUNT];

  /**
   * Capture return addresses from |t|'s stack. The returned
   * address list may not be actual return addresses (in optimized code,
   * will probably not be), but they will be a function of the task's current
   * state, so may be useful for distinguishing this state from other states.
   */
  ReturnAddressList() {}
  explicit ReturnAddressList(Task* t);

  bool operator==(const ReturnAddressList& other) const {
    return memcmp(addresses, other.addresses, sizeof(addresses)) == 0;
  }
  bool operator!=(const ReturnAddressList& other) const {
    return !(*this == other);
  }
};

} // namespace rr

#endif /* RR_RETURNADDRESSLIST_H_ */
