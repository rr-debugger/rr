/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define BUF_SIZE 0x20000
#define FILE_BUFS 10
#define ITERATIONS 100

int main(void) {
  int i, j;
  int fd = open("tmp.txt", O_RDWR | O_CREAT | O_EXCL);
  char buf[BUF_SIZE];
  test_assert(fd >= 0);
  test_assert(0 == unlink("tmp.txt"));
  memset(buf, 1, sizeof(buf));
  for (i = 0; i < FILE_BUFS; ++i) {
    test_assert(sizeof(buf) == write(fd, buf, sizeof(buf)));
  }

  for (i = 0; i < ITERATIONS; ++i) {
    test_assert(0 == lseek(fd, 0, SEEK_SET));
    for (j = 0; j < FILE_BUFS; ++j) {
      memset(buf, 0, sizeof(buf));
      test_assert(sizeof(buf) == read(fd, buf, sizeof(buf)));
      test_assert(buf[0] == 1);
      test_assert(buf[sizeof(buf) - 1] == 1);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
