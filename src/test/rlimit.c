/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct rlimit* r;
  struct rlimit* r2;

  ALLOCATE_GUARD(r, 0);
  ALLOCATE_GUARD(r2, 'x');

  test_assert(0 == getrlimit(RLIMIT_FSIZE, r));
  test_assert(r->rlim_cur > 0);
  test_assert(r->rlim_max > 0);
  VERIFY_GUARD(r);

  r->rlim_cur /= 2;
  test_assert(0 == setrlimit(RLIMIT_FSIZE, r));
  VERIFY_GUARD(r);

  test_assert(0 == getrlimit(RLIMIT_FSIZE, r2));
  test_assert(r2->rlim_cur == r->rlim_cur);
  VERIFY_GUARD(r2);

  test_assert(0 == prlimit(0, RLIMIT_FSIZE, r, r2));
  test_assert(r2->rlim_cur == r->rlim_cur);
  VERIFY_GUARD(r);
  VERIFY_GUARD(r2);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
