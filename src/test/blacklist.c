/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char file_name[] = "rr-test-blacklist-file_name";

int main(void) {
  int fd = syscall(SYS_open, file_name, O_RDONLY);
  test_assert(fd < 0);
  test_assert(errno == ENOENT);
  fd = syscall(SYS_openat, AT_FDCWD, file_name, O_RDONLY);
  test_assert(fd < 0);
  test_assert(errno == ENOENT);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
