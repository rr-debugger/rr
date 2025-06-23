/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  uint64_t iteration = 0;
  int pipe_fds[2];
  pipe(pipe_fds);

  // Write once to get the syscallbuf primed.
  write(pipe_fds[1], "hi\n", 3);

  atomic_puts("ready");
  atomic_puts("EXIT-SUCCESS");

  // Write again.
  write(pipe_fds[1], "hi\n", 3);

  while (iteration < UINT64_MAX) {
    iteration += 1;
    // Don't let the compiler delete this loop.
    asm("" : : : "memory");
  }
  return 0;
}
