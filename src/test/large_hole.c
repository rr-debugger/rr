/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
#ifdef __x86_64__
  off_t size = ((off_t)100)*1024*1024*1024;
  char* p;
  int fd = open("big", O_RDWR | O_TRUNC | O_CREAT, 0700);
  test_assert(pwrite64(fd, "x", 1, size) == 1);
  p = (char*)mmap(NULL, size + 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  p[size/2] = 1;
  p[size/2 + 65536] = 1;
  test_assert(0 == munmap(p, size + 1));

  test_assert(fallocate64(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, size/2, 4096) == 0);
  p = (char*)mmap(NULL, size + 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[size/2] == 0);
  test_assert(p[size/2 + 65536] == 1);
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
