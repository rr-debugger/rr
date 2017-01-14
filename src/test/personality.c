/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#include <sys/personality.h>

int main(void) {
  personality(PER_LINUX);
  test_assert(personality(0xffffffff) == PER_LINUX);

  personality(PER_LINUX32);
  test_assert(personality(0xffffffff) == PER_LINUX32);

  personality(ADDR_NO_RANDOMIZE);
  test_assert(personality(0xffffffff) == ADDR_NO_RANDOMIZE);

  personality(ADDR_COMPAT_LAYOUT);
  test_assert(personality(0xffffffff) == ADDR_COMPAT_LAYOUT);

  personality(ADDR_LIMIT_32BIT);
  test_assert(personality(0xffffffff) == ADDR_LIMIT_32BIT);

  personality(ADDR_LIMIT_3GB);
  test_assert(personality(0xffffffff) == ADDR_LIMIT_3GB);

  personality(MMAP_PAGE_ZERO);
  test_assert(personality(0xffffffff) == MMAP_PAGE_ZERO);

  /* Not tested yet: May need to update some checks in rr
     personality(READ_IMPLIES_EXEC);
     test_assert(personality(0xffffffff) == READ_IMPLIES_EXEC);
  */

  personality(SHORT_INODE);
  test_assert(personality(0xffffffff) == SHORT_INODE);

  personality(STICKY_TIMEOUTS);
  test_assert(personality(0xffffffff) == STICKY_TIMEOUTS);

  personality(UNAME26);
  test_assert(personality(0xffffffff) == UNAME26);

  personality(WHOLE_SECONDS);
  test_assert(personality(0xffffffff) == WHOLE_SECONDS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
