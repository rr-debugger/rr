/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct stat* buf;
  int ret;

  ALLOCATE_GUARD(buf, 0);
  ret = fstatat(AT_FDCWD, ".", buf, 0);
  VERIFY_GUARD(buf);

  if (ret < 0) {
    test_assert(errno == ENOSYS);
    atomic_puts("EXIT-SUCCESS");
    return 0;
  } else {
    test_assert(buf->st_size != 0);
  }

  int dir_fd = open("/proc/self", O_PATH);
  test_assert(dir_fd >= 0);

  ALLOCATE_GUARD(buf, 0);
  ret = fstatat(dir_fd, "exe", buf, 0);
  VERIFY_GUARD(buf);

  test_assert(ret == 0);
  test_assert(buf->st_size != 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
