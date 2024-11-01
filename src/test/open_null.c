/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "util.h"
#include <unistd.h>

int main(void) {
  // Use syscall(2) because the glibc prototype for open(2) might enforce that
  // it's nonnull.
  int fd = syscall(SYS_open, NULL, O_RDONLY);
  test_assert(fd == -1);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
