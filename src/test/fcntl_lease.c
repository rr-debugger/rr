/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("tmpfile", O_RDWR | O_CREAT | O_TRUNC, 0600);
  test_assert(fd >= 0);
  int ret = fcntl(fd, F_SETLEASE, F_WRLCK);
  test_assert(!ret);
  ret = fcntl(fd, F_GETLEASE);
  test_assert(ret == F_WRLCK);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
