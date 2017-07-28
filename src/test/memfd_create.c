/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TEST_MEMFD "foo"

int main(void) {
  int fd;

  /* There's no libc helper for this syscall. */
  fd = syscall(RR_memfd_create, TEST_MEMFD, 0);
  if (-1 == fd && ENOSYS == errno) {
    atomic_puts("SYS_memfd_create not supported on this kernel");
  } else {
    test_assert(fd >= 0);
    test_assert(0 == close(fd));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
