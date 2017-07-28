/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int k = 2;

static void breakpoint(void) {}

static void breakpoint2(void) {}

int main(void) {
  int i;
  int j;
  int fd = open("/dev/null", O_WRONLY);

  test_assert(fd >= 0);

  /* We need to test reverse-continue through
     a bunch of breakpoints when the next event
     is a syscallbuf-flush. So we need the next event to
     be syscall-buffered. Do a write here so that the syscall
     is patched now, not later. */
  test_assert(1 == write(fd, ".", 1));

  for (i = 0; i < 2000000; ++i) {
    breakpoint2();
    for (j = 0; j < 10; ++j) {
      k = k * 37;
    }
  }
  breakpoint();

  test_assert(1 == write(fd, ".", 1));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
