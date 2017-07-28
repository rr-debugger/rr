/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct sched_attr* attr;

  ALLOCATE_GUARD(attr, 'x');
  test_assert(0 == sched_getattr(0, attr, sizeof(*attr), 0));
  /* Don't check specific scheduling parameters in case someone
     is running the rr tests with low priority or something like that */
  test_assert(attr->size == sizeof(*attr));
  test_assert(attr->flags == 0);
  VERIFY_GUARD(attr);

  test_assert(0 == sched_setattr(0, attr, 0));
  VERIFY_GUARD(attr);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
