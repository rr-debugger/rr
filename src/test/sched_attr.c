/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

int main(void) {
  struct sched_attr* attr;
  ALLOCATE_GUARD(attr, 'x');
  syscall(__NR_sched_getattr, 0, attr, sizeof(*attr), 0);
  /* Don't check specific scheduling parameters in case someone
     is running the rr tests with low priority or something like that */
  test_assert(attr->size == sizeof(*attr));
  test_assert(attr->sched_flags == 0);
  VERIFY_GUARD(attr);

  test_assert(0 == syscall(__NR_sched_setattr, 0, attr, 0));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
