/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = memfd_create("temp", 0);
  char buf[4096];
  int size = sizeof(buf);
  int ret;
  uint8_t* p;
  memset(buf, 1, size);
  ret = write(fd, buf, size);
  test_assert(ret == size);
  p = (uint8_t*)mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);

  memset(buf, 0, size);
  ret = pwrite(fd, buf, size, 0);
  test_assert(ret == size);

  p = (uint8_t*)mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
