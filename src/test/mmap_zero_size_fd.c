/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char name[] = "/tmp/rr-mmap-zero-size-XXXXXX";
  int fd = mkstemp(name);
  ftruncate(fd, 0);
  void* mmap_addr =
      mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  test_assert(mmap_addr != MAP_FAILED);

  test_assert(0 == unlink(name));

  atomic_puts("EXIT-SUCCESS");
}
