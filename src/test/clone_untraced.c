/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];

static int run_thread(__attribute__((unused)) void* p) {
  test_assert(1 == write(pipe_fds[1], ".", 1));
  return 0;
}

int main(void) {
  char* stack = (char*)xmalloc(65536) + 65536;
  int ret;
  char ch;

  test_assert(0 == pipe(pipe_fds));
  ret = clone(run_thread, stack, CLONE_UNTRACED, NULL);
  test_assert(ret >= 0);
  test_assert(1 == read(pipe_fds[0], &ch, 1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
