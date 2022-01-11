/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  unsigned long iteration = 0;
  int pipe_fds[2];
  pipe(pipe_fds);

  // Write once to get the syscallbuf primed.
  write(pipe_fds[1], "hi\n", 3);

  atomic_puts("ready");
  atomic_puts("EXIT-SUCCESS");

  // Write again.
  write(pipe_fds[1], "hi\n", 3);

  while (iteration < ULONG_MAX) {
    iteration += 1;
  }
  return 0;
}
