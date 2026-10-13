/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Recorded in chaos mode by chaos_buffered_syscalls.run, which checks that
   most of these read()s and write()s went through the syscall buffer. Chaos
   mode makes the syscall buffer trace runs of 1 to 50 of the syscalls that
   it can force to be traced (read() and write() among them), each preceded
   by a run of buffered ones ten times as long less 50 (if that's positive),
   so on average about 11% of them are traced. */

#define ITERATIONS 2000

int main(void) {
  int fds[2];
  char ch = 'x';
  int i;

  test_assert(0 == pipe(fds));
  for (i = 0; i < ITERATIONS; ++i) {
    test_assert(1 == write(fds[1], &ch, 1));
    test_assert(1 == read(fds[0], &ch, 1));
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
