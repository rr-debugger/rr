/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("/dev/sda1", O_NONBLOCK | O_RDONLY);
  if (fd < 0) {
    test_assert(errno == EACCES || errno == ENOENT);
    atomic_printf("Opening a block device usually needs root permission, skipping test\n");
  } else {
    int sector_size;
    test_assert(0 == ioctl(fd, BLKSSZGET, &sector_size));
    atomic_printf("BLKSSZGET returned sector_size=%d\n", sector_size);

    unsigned long long bytes = 0;
    test_assert(0 == ioctl(fd, BLKGETSIZE64, &bytes));
    atomic_printf("BLKGETSIZE64 returned bytes=%llu\n", bytes);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
