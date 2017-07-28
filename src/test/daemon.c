/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];

static int do_child(void) {
  /* Daemonize */
  if (fork()) {
    return 0;
  }
  setsid();
  write(pipe_fds[1], "x", 1);
  sleep(1000000);
  return 0;
}

int main(void) {
  pid_t child;
  char ch;

  test_assert(0 == pipe(pipe_fds));

  child = fork();

  if (!child) {
    return do_child();
  }

  test_assert(1 == read(pipe_fds[0], &ch, 1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
