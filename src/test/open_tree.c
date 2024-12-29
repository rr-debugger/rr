/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = syscall(RR_open_tree, AT_FDCWD, "/mnt", 0);
  if (fd < 0 && errno == ENOSYS) {
    atomic_puts("open_tree not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(fd >= 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
