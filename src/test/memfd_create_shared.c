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
    void* p1;
    test_assert(fd >= 0);
    ftruncate(fd, 4096);
    /* Create a shared, executable mapping to make sure that works.
       In the past, rr depended on /tmp being mounted exec for this to work. */
    p1 = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
    test_assert(p1 != MAP_FAILED);
    test_assert(0 == close(fd));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
