/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  char* p;
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = open("small", O_RDWR | O_TRUNC | O_CREAT, 0700);
  test_assert(0 == ftruncate(fd, page_size*7));
  pwrite(fd, "x", 1, page_size);
  pwrite(fd, "y", 1, page_size*3);
  pwrite(fd, "z", 1, page_size*5);
  p = (char*)mmap(NULL, page_size*7, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[page_size] == 'x');
  test_assert(p[page_size*3] == 'y');
  test_assert(p[page_size*5] == 'z');
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
