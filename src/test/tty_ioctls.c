/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  int fd = open("/dev/ptmx", O_RDONLY);
  test_assert(fd >= 0);

  atomic_printf("tty ptsname = %s\n", ptsname(fd));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
