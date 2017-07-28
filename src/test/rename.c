/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  static const char file_path[] = "rr-test-file";
  static const char file2_path[] = "rr-test-file2";
  int ret;
  int fd = open(file_path, O_WRONLY | O_CREAT, 0700);
  test_assert(0 == close(fd));

  test_assert(0 == rename(file_path, file2_path));
  test_assert(0 == renameat(AT_FDCWD, file2_path, AT_FDCWD, file_path));
  ret = syscall(RR_renameat2, AT_FDCWD, file_path, AT_FDCWD, file2_path, 0);
  if (-1 == ret && errno == ENOSYS) {
    test_assert(0 == unlink(file_path));
  } else {
    test_assert(0 == ret);
    test_assert(0 == unlink(file2_path));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
