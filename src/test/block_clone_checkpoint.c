/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define BUF_SIZE 0x20000

static void breakpoint(void) { event_syscall(); }

int main(void) {
  int i;
  int fd = open("tmp.txt", O_RDWR | O_CREAT | O_EXCL);
  char buf[BUF_SIZE];
  test_assert(fd >= 0);
  test_assert(0 == unlink("tmp.txt"));
  for (i = 1; i <= 10; ++i) {
    memset(buf, i, sizeof(buf));
    test_assert(sizeof(buf) == write(fd, buf, sizeof(buf)));
  }

  test_assert(0 == lseek(fd, 0, SEEK_SET));
  memset(buf, 0, sizeof(buf));
  for (i = 1; i <= 10; ++i) {
    test_assert(sizeof(buf) == read(fd, buf, sizeof(buf)));
    test_assert(buf[0] == i);
    test_assert(buf[sizeof(buf) - 1] == i);
    breakpoint();
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
