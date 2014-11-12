/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  struct tms buf = { -1, -1, -1, -1 };
  clock_t t = times(&buf);
  test_assert(buf.tms_cutime == 0);
  test_assert(buf.tms_utime >= 0);

  atomic_printf("tms_utime = %lld\n", (long long)buf.tms_utime);
  atomic_printf("result = %lld\n", (long long)t);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
