/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("dummy.txt", O_RDWR | O_CREAT | O_TRUNC, 0600);
  int ret;
  test_assert(fd >= 0);
  ret = write(fd, "x", 1);
  test_assert(ret == 1);
  ret = sync_file_range(fd, 0, 1, SYNC_FILE_RANGE_WAIT_BEFORE);
  test_assert(ret == 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
