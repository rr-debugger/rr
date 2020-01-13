/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SIZE 128*1024

int main(void) {
  int fd = open("test.out", O_RDWR | O_DIRECT | O_CREAT | O_TRUNC, 0600);
  void* p;
  int ret = posix_memalign(&p, SIZE, SIZE);
  if (fd < 0 && errno == EINVAL) {
    atomic_puts("Filesystem doesn't support O_DIRECT; skipping");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(fd >= 0);
  test_assert(ret == 0);

  ret = write(fd, p, SIZE);
  test_assert(ret == SIZE);

  ret = pread(fd, p, SIZE, 0);
  test_assert(ret == SIZE);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
