/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;

  /* There's no libc helper for this syscall. */
  fd = syscall(RR_memfd_create, NULL, 0);
  if (ENOSYS == errno) {
    atomic_puts("SYS_memfd_create not supported on this kernel");
  } else {
    test_assert(fd == -1);
    test_assert(errno == EFAULT);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
