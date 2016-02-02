/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define TEST_MEMFD "foo"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001
#define MFD_ALLOW_SEALING 0x0002
#endif

int main(void) {
  int fd;

  /* There's no libc helper for this syscall. */
  fd = syscall(RR_memfd_create, TEST_MEMFD, MFD_ALLOW_SEALING);
  if (-1 == fd && ENOSYS == errno) {
    atomic_puts("SYS_memfd_create not supported on this kernel");
  } else {
    test_assert(fd >= 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
