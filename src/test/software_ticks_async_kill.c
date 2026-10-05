/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h) and ticks
 * between buffered syscalls, SIGKILLed while it runs (see
 * async_kill_with_syscallbuf). A kill that lands between the commit of a
 * syscallbuf record and the syscallbuf's forced tick is recorded as a flush
 * and a SCHED at the same ticks, which replay must recognize at the flush's
 * last breakpoint instead of running on to the next syscall. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

static void __attribute__((noinline)) tick(void) { RR_SOFTTICK(); }

int main(void) {
  int pipe_fds[2];
  char chars[16];
  memset(chars, 0, sizeof(chars));
  test_assert(0 == pipe(pipe_fds));

  atomic_puts("ready");
  atomic_puts("EXIT-SUCCESS");

  while (1) {
    tick();
    test_assert(sizeof(chars) == write(pipe_fds[1], chars, sizeof(chars)));
    tick();
    test_assert(sizeof(chars) == read(pipe_fds[0], chars, sizeof(chars)));
  }
  return 0;
}
