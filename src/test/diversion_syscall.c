/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  // We will make use of the fact that fd 3 is closed. Just to be sure the
  // parent didn't leak anything, close it (in the normal case, this'll fail,
  // but that's ok).
  close(3);

  // Do a bunch of bufferable system calls
  int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  test_assert(fd == 3);

  // At this breakpoint, we'll attempt to open a file during the diversion
  breakpoint();

  // More bufferable syscalls
  for (int i = 1; i < 10; ++i) {
    write(fd, "Hello", 5);
  }
}
