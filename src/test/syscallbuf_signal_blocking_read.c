/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("dummy.txt", O_RDWR | O_CREAT | O_EXCL, 0700);
  char* buf = malloc(100 * 1024 * 1024);
  int i;
  unlink("dummy.txt");

  for (i = 0; i < 1000; ++i) {
    /* Do a large read that can't be buffered so will cause a traced
       read, though we will try to do an ioctl FIOCLONERANGE on it first
       (which we're testing for interference with many TIME_SLICE_SIGNALs) */
    ssize_t ret = read(fd, buf, 100 * 1024 * 1024);
    test_assert(ret == 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
