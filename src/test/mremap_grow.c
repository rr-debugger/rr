/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("temp", O_RDWR | O_CREAT, 0700);
  size_t page_size = sysconf(_SC_PAGESIZE);
  char buf[page_size * 2];
  char* p;

  test_assert(fd >= 0);
  test_assert(0 == unlink("temp"));

  memset(buf, 1, sizeof(buf));
  test_assert((ssize_t)sizeof(buf) == write(fd, buf, sizeof(buf)));

  p = (char*)mmap(NULL, page_size, PROT_READ, MAP_PRIVATE, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == 1);

  p = (char*)mremap(p, page_size, page_size * 2, MREMAP_MAYMOVE);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == 1);
  test_assert(p[page_size] == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
