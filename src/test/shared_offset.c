/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = syscall(RR_memfd_create, "shared", 0);
  if (fd < 0 && errno == ENOSYS) {
    atomic_puts("SYS_memfd_create not supported on this kernel");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(fd >= 0);
  test_assert(0 == ftruncate(fd, page_size*2));
  char* map = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
    MAP_SHARED, fd, page_size);
  test_assert(map != MAP_FAILED);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
