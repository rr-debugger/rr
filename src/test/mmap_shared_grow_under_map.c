/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = open("file", O_RDWR | O_CREAT | O_TRUNC, 0700);
  char* p;
  test_assert(fd >= 0);
  unlink("file");

  p = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  ftruncate(fd, page_size);
  p[0] = 'x';
  atomic_puts("EXIT-SUCCESS");

  return 0;
}
