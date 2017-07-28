/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct tms* buf;
  clock_t t;

  ALLOCATE_GUARD(buf, -1);
  test_assert((t = times(buf)) != (clock_t)-1);
  test_assert(buf->tms_cutime == 0);
  test_assert(buf->tms_utime >= 0);
  VERIFY_GUARD(buf);

  atomic_printf("tms_utime = %lld\n", (long long)buf->tms_utime);
  atomic_printf("result = %lld\n", (long long)t);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
