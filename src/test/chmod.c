/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  static const char file_path[] = "rr-test-file";
  int fd = open(file_path, O_WRONLY | O_CREAT, 0);
  test_assert(fd >= 0);

  test_assert(0 == chmod(file_path, 0400));
  test_assert(0 == access(file_path, R_OK));
  test_assert(0 == fchmod(fd, 0200));
  test_assert(0 == access(file_path, W_OK));
  test_assert(0 == fchmodat(AT_FDCWD, file_path, 0400, 0));
  test_assert(0 == access(file_path, R_OK));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
