/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  /* There's not a (simple) way to meaningfully test fadvise,
   * since it only provides optimization hints, so this just
   * checks that rr doesn't blow up when it sees one. */
  posix_fadvise(-1, 0, 0, POSIX_FADV_NORMAL);
  syscall(SYS_fadvise64, -1, 0, 0, POSIX_FADV_NORMAL);
#if defined(SYS_fadvise64_64)
  syscall(SYS_fadvise64_64, -1, POSIX_FADV_NORMAL, 0, 0);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
