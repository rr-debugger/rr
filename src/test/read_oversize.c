/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("tmp", O_CREAT | O_RDWR, 0700);
  char buf[100];
  int ret;

  test_assert(fd >= 0);
  memset(buf, 1, sizeof(buf));
  test_assert(sizeof(buf) == write(fd, buf, sizeof(buf)));

  test_assert(0 == lseek(fd, 0, SEEK_SET));
  ret = read(fd, buf, UINTPTR_MAX - 0xfff);
  if (ret < 0) {
    /* x86-64 returns EFAULT here. I'm not sure why. */
    test_assert(EFAULT == errno);
  } else {
    test_assert(100 == ret);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
