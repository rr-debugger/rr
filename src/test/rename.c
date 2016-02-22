/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  static const char file_path[] = "rr-test-file";
  static const char file2_path[] = "rr-test-file2";
  int fd = open(file_path, O_WRONLY | O_CREAT, 0700);
  test_assert(0 == close(fd));

  test_assert(0 == rename(file_path, file2_path));
  test_assert(0 == renameat(AT_FDCWD, file2_path, AT_FDCWD, file_path));
  test_assert(
      0 == syscall(RR_renameat2, AT_FDCWD, file_path, AT_FDCWD, file2_path, 0));

  test_assert(0 == unlink(file2_path));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
