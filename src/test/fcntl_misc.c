/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fds[2];
  int ret;
  size_t page_size = sysconf(_SC_PAGESIZE);

  ret = pipe(fds);
  test_assert(ret == 0);
  ret = fcntl(fds[0], F_SETPIPE_SZ, 2 * page_size);
  test_assert(ret == (int)(2 * page_size));
  ret = fcntl(fds[1], F_GETPIPE_SZ);
  test_assert(ret == (int)(2 * page_size));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
