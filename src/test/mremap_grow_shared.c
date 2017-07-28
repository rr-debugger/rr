/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(__attribute((unused)) int argc, char* argv[]) {
  int fd = open(argv[0], O_RDONLY);
  size_t page_size = sysconf(_SC_PAGESIZE);
  char buf[page_size * 2];
  char* p;

  test_assert(fd >= 0);
  test_assert((ssize_t)sizeof(buf) == read(fd, buf, sizeof(buf)));

  p = (char*)mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == buf[0]);

  p = (char*)mremap(p, page_size, page_size * 2, MREMAP_MAYMOVE);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == buf[0]);
  test_assert(p[page_size] == buf[page_size]);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
