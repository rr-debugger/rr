/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  struct rlimit r = { 0, 0 };
  struct rlimit r2 = { 0, 0 };

  test_assert(0 == getrlimit(RLIMIT_FSIZE, &r));
  test_assert(r.rlim_cur > 0);
  test_assert(r.rlim_max > 0);

  r.rlim_cur /= 2;
  test_assert(0 == setrlimit(RLIMIT_FSIZE, &r));

  test_assert(0 == getrlimit(RLIMIT_FSIZE, &r2));
  test_assert(r2.rlim_cur == r.rlim_cur);

  test_assert(0 == prlimit(0, RLIMIT_FSIZE, &r, &r2));
  test_assert(r2.rlim_cur == r.rlim_cur);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
