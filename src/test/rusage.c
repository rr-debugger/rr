/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct rusage* r;

  ALLOCATE_GUARD(r, 0);
  test_assert(0 == getrusage(RUSAGE_SELF, r));
  test_assert(r->ru_maxrss > 0);
  VERIFY_GUARD(r);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
