/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int rr_personality(unsigned long persona) {
  long ret = syscall(RR_personality, persona);
  if (-4096 < ret && ret < 0) {
    errno = -ret;
    return -1;
  }
  return ret;
}

int main(void) {
  rr_personality(PER_LINUX);
  test_assert(rr_personality(0xffffffff) == PER_LINUX);

  rr_personality(PER_LINUX32);
  test_assert(rr_personality(0xffffffff) == PER_LINUX32);

  rr_personality(ADDR_NO_RANDOMIZE);
  test_assert(rr_personality(0xffffffff) == ADDR_NO_RANDOMIZE);

  rr_personality(ADDR_COMPAT_LAYOUT);
  test_assert(rr_personality(0xffffffff) == ADDR_COMPAT_LAYOUT);

  rr_personality(ADDR_LIMIT_32BIT);
  test_assert(rr_personality(0xffffffff) == ADDR_LIMIT_32BIT);

  rr_personality(ADDR_LIMIT_3GB);
  test_assert(rr_personality(0xffffffff) == ADDR_LIMIT_3GB);

  rr_personality(MMAP_PAGE_ZERO);
  test_assert(rr_personality(0xffffffff) == MMAP_PAGE_ZERO);

  /* Not tested yet: May need to update some checks in rr
     rr_personality(READ_IMPLIES_EXEC);
     test_assert(rr_personality(0xffffffff) == READ_IMPLIES_EXEC);
  */

  rr_personality(SHORT_INODE);
  test_assert(rr_personality(0xffffffff) == SHORT_INODE);

  rr_personality(STICKY_TIMEOUTS);
  test_assert(rr_personality(0xffffffff) == STICKY_TIMEOUTS);

  rr_personality(UNAME26);
  test_assert(rr_personality(0xffffffff) == UNAME26);

  rr_personality(WHOLE_SECONDS);
  test_assert(rr_personality(0xffffffff) == WHOLE_SECONDS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
