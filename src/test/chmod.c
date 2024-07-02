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
  test_assert(0 == syscall(RR_fchmodat, AT_FDCWD, file_path, 0400));
  test_assert(0 == syscall(RR_fchmodat2, AT_FDCWD, file_path, 0400, 0) || errno == ENOSYS);
  test_assert(0 == access(file_path, R_OK));
  test_assert(0 == faccessat(AT_FDCWD, file_path, R_OK, AT_SYMLINK_NOFOLLOW) || errno == ENOSYS);
  test_assert(0 == syscall(RR_faccessat2, AT_FDCWD, file_path, R_OK, AT_SYMLINK_NOFOLLOW) || errno == ENOSYS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
