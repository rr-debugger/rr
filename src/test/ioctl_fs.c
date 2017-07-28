/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("dummy.txt", O_RDWR | O_CREAT, 0600);
  long version;
  long flags;
  int ret;

  test_assert(fd >= 0);
  ret = ioctl(fd, FS_IOC_GETVERSION, &version);
  if (ret < 0) {
    test_assert(errno == ENOTTY);
  } else {
    atomic_printf("version=%ld\n", version);
  }
  ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
  if (ret < 0) {
    test_assert(errno == ENOTTY);
  } else {
    atomic_printf("flags=%lx\n", flags);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
