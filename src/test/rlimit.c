/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int kernel_is_32bit_x86(void)
{
#if defined(__i386__)
  struct utsname buf;
  if (uname(&buf) != 0)
    return 0;

  if (strcmp(buf.machine, "i686") == 0) // running at a 32bit kernel
    return 1;
#endif
  return 0;
}

int main(void) {
  struct rlimit* r;
  struct rlimit* r2;

  ALLOCATE_GUARD(r, 0);
  ALLOCATE_GUARD(r2, 'x');

  test_assert(0 == getrlimit(RLIMIT_FSIZE, r));
  test_assert(r->rlim_cur > 0);
  test_assert(r->rlim_max > 0);
  VERIFY_GUARD(r);

  /* When running a 32-bit kernel and using the 64-bit rlimit struct,
   * a value above 0xfffffffe fails. */
  if (kernel_is_32bit_x86())
    r->rlim_cur &= 0xffffffff;

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
