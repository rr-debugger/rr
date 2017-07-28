/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;

  fd = fcntl(1, F_DUPFD, 3);
  test_assert(fd >= 3);
  close(1);

  fd = dup2(fd, 1);
  test_assert(fd == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
