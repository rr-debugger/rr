/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int fd;

static int recurse(int n) {
  char ch[8];
  if (n <= 0) {
    return 0;
  }
  /* Use a system call that goes through SYSENTER on x86-32 */
  test_assert(8 == read(fd, ch, 8));
  return recurse(n - 1) + ch[0];
}

int main(void) {
  fd = open("/dev/zero", O_RDONLY);
  test_assert(fd >= 0);

  recurse(10000);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
