/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct timeval* tv;
  struct timezone* tz;

  ALLOCATE_GUARD(tv, 0);
  ALLOCATE_GUARD(tz, 'x');
  test_assert(0 == gettimeofday(tv, tz));
  test_assert(tv->tv_sec > 0);
  test_assert(tz->tz_dsttime == 0); /* always zero on Linux */
  VERIFY_GUARD(tv);
  VERIFY_GUARD(tz);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
