/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define BUF_COUNT (int)(0x20000 / sizeof(int))
#define FILE_BUFS 10
#define ITERATIONS 100

int main(void) {
  int i, j, count;
  int fd = open("tmp.txt", O_RDWR | O_CREAT | O_EXCL);
  int buf[BUF_COUNT];
  test_assert(fd >= 0);
  test_assert(0 == unlink("tmp.txt"));
  count = 0;
  for (i = 0; i < FILE_BUFS; ++i) {
    for (j = 0; j < BUF_COUNT; ++j) {
      buf[j] = count++;
    }
    test_assert(sizeof(buf) == write(fd, buf, sizeof(buf)));
  }

  for (i = 0; i < ITERATIONS; ++i) {
    count = 0;
    test_assert(0 == lseek(fd, 0, SEEK_SET));
    for (j = 0; j < FILE_BUFS; ++j) {
      memset(buf, 0, sizeof(buf));
      test_assert(sizeof(buf) == read(fd, buf, sizeof(buf)));
      test_assert(buf[0] == count);
      test_assert(buf[BUF_COUNT - 1] == count + BUF_COUNT - 1);
      count += BUF_COUNT;
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
