/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
#ifdef __x86_64__
  unsigned long addr;
  test_assert(0 == syscall(SYS_arch_prctl, ARCH_GET_FS, &addr));
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
