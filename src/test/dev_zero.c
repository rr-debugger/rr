/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("/dev/zero", O_RDONLY);
  test_assert(fd >= 0);
  void* ptr = mmap(NULL, 0x200000, PROT_READ, MAP_PRIVATE, fd, 0);
  test_assert(ptr != NULL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
