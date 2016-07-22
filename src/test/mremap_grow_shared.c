/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(__attribute((unused)) int argc, char* argv[]) {
  int fd = open(argv[0], O_RDONLY);
  char buf[PAGE_SIZE * 2];
  char* p;

  test_assert(fd >= 0);
  test_assert((ssize_t)sizeof(buf) == read(fd, buf, sizeof(buf)));

  p = (char*)mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == buf[0]);

  p = (char*)mremap(p, PAGE_SIZE, PAGE_SIZE * 2, MREMAP_MAYMOVE);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == buf[0]);
  test_assert(p[PAGE_SIZE] == buf[PAGE_SIZE]);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
