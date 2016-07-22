/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  int fd = open("temp", O_RDWR | O_CREAT, 0700);
  char buf[PAGE_SIZE * 2];
  char* p;

  test_assert(fd >= 0);
  test_assert(0 == unlink("temp"));

  memset(buf, 1, sizeof(buf));
  test_assert((ssize_t)sizeof(buf) == write(fd, buf, sizeof(buf)));

  p = (char*)mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == 1);

  p = (char*)mremap(p, PAGE_SIZE, PAGE_SIZE * 2, MREMAP_MAYMOVE);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == 1);
  test_assert(p[PAGE_SIZE] == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
