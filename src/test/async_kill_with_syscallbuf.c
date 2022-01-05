/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int pipe_fds[2];
  int iteration = 0;
  char chars[100];
  pipe(pipe_fds);
  memset(chars, 0, sizeof(chars));

  atomic_puts("ready");
  atomic_puts("EXIT-SUCCESS");

  while (1) {
    int n = (iteration % 100) + 1;
    test_assert(n == write(pipe_fds[1], chars, n));
    test_assert(n == read(pipe_fds[0], chars, n));
    iteration += 1;
  }
  return 0;
}
