/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const char file_name[] = "rr-test-blacklist-file_name";

int main(void) {
  int fd;
  int dirfd;
  char buf[PATH_MAX];

  open(file_name, O_CREAT | O_WRONLY, 0700);

#ifdef SYS_open
  fd = syscall(SYS_open, file_name, O_RDONLY);
  test_assert(fd < 0);
  test_assert(errno == ENOENT);
#endif

  fd = syscall(SYS_openat, AT_FDCWD, file_name, O_RDONLY);
  test_assert(fd < 0);
  test_assert(errno == ENOENT);

  getcwd(buf, PATH_MAX);
  dirfd = syscall(SYS_openat, -1, buf, O_PATH);
  test_assert(dirfd >= 0);
  fd = syscall(SYS_openat, dirfd, "rr-test-blacklist-file_name", O_RDONLY);
  test_assert(fd < 0);
  test_assert(errno == ENOENT);

  unlink(file_name);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
