/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fds[2];
  int ret;
  size_t page_size = sysconf(_SC_PAGESIZE);

  ret = pipe(fds);
  test_assert(ret == 0);
  size_t new_size = 2 * page_size;
  ret = fcntl(fds[0], F_SETPIPE_SZ, new_size);
  if (ret == -EPERM) {
    // Pipe resource buffer exhausted, e.g. due to
    // /proc/sys/fs/pipe-max-size or /proc/sys/fs/pipe-user-pages-{hard, soft}.
    atomic_puts("Pipe buffer exhausted during F_SETPIPE_SZ. Skipping.");
    new_size = page_size;
  } else {
    test_assert(ret == (int)(new_size));
  }

  ret = fcntl(fds[1], F_GETPIPE_SZ);
  test_assert(ret == (int)(new_size));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
