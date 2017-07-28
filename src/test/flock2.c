/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
/* Test for the 'flock' system call. */

#include "util.h"

#define FILENAME "foo.txt"

int main(void) {
  int fd;
  int result;

  fd = open(FILENAME, O_CREAT | O_EXCL | O_RDWR, 0600);
  test_assert(fd >= 0);

  result = flock(fd, LOCK_SH);
  test_assert(result == 0);

  result = flock(fd, LOCK_EX);
  test_assert(result == 0);

  result = flock(fd, LOCK_UN);
  test_assert(result == 0);

  result = close(fd);
  test_assert(result == 0);

  result = flock(fd, LOCK_EX);
  test_assert(result < 0);
  test_assert(errno == EBADF);

  unlink(FILENAME);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
