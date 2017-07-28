/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char buf[128 * 1024];

int main(void) {
  stack_t* ss;
  stack_t* oss;

  ALLOCATE_GUARD(ss, 'x');
  ss->ss_sp = buf;
  ss->ss_flags = 0;
  ss->ss_size = sizeof(buf);
  test_assert(0 == sigaltstack(ss, NULL));
  VERIFY_GUARD(ss);

  ALLOCATE_GUARD(oss, 'y');
  test_assert(0 == sigaltstack(ss, oss));
  test_assert(oss->ss_sp == buf);
  test_assert(oss->ss_flags == 0);
  test_assert(oss->ss_size == sizeof(buf));
  VERIFY_GUARD(ss);
  VERIFY_GUARD(oss);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
