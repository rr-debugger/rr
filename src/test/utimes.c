/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const int MOD_TIME = 888888;
static const int ACCESS_TIME = 999999;

int main(void) {
  char path[] = "rr-test-file-XXXXXX";
  int fd = mkstemp(path);
  struct utimbuf utim = { ACCESS_TIME, MOD_TIME };
  struct timeval tv[2] = { { ACCESS_TIME + 1, 0 }, { MOD_TIME + 1, 0 } };
  struct stat st;

  test_assert(0 <= fd);

  test_assert(0 == utime(path, &utim));
  test_assert(0 == fstat(fd, &st));
  test_assert(st.st_atime == ACCESS_TIME);
  test_assert(st.st_mtime == MOD_TIME);

  test_assert(0 == utimes(path, tv));
  test_assert(0 == fstat(fd, &st));
  test_assert(st.st_atime == ACCESS_TIME + 1);
  test_assert(st.st_mtime == MOD_TIME + 1);

  test_assert(0 == unlink(path));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
