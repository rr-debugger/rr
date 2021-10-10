/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TEST_MEMFD "bar"
/* On my system (5.4.0-67-generic) /proc/pid/mem can take 2GB - 1 page at once. */
#define MEMFD_SIZE (2LL * 1024 * 1024 * 1024)

int main(void) {
#if defined(__i386__)
  atomic_puts("Skipping test on 32 bit");
#else
  int fd;

  /* There's no libc helper for this syscall. */
  fd = syscall(RR_memfd_create, TEST_MEMFD, 0);
  if (-1 == fd && ENOSYS == errno) {
    atomic_puts("SYS_memfd_create not supported on this kernel");
  } else {
    test_assert(fd >= 0);
    if (0 != ftruncate(fd, 2LL * 1024 * 1024 * 1024)) {
      atomic_puts("Could not create 2GB memfd");
    } else {
      void *p1, *p2;
      /* Map it once */
      p1 = mmap(0, MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      test_assert(p1 != MAP_FAILED);
      *(uint32_t*)p1 = 0xdeadbeef;
      /* Map it again */
      p2 = mmap(0, MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      test_assert(p2 != MAP_FAILED);
      test_assert(*(uint32_t*)p2 == 0xdeadbeef);
      test_assert(0 == close(fd));
    }
  }
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
