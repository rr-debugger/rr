/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  static const char name[] = "temp";
  int fd = open(name, O_CREAT | O_RDWR | O_EXCL, 0600);
  ftruncate(fd, 0);
  void* mmap_addr =
      mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  test_assert(mmap_addr != MAP_FAILED);

  test_assert(0 == unlink(name));

  atomic_puts("EXIT-SUCCESS");
}
