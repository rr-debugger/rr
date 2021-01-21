/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];
static volatile int big_size = 1024 * 1024 * 50;

int main(void) {
  pid_t child;
  char buf[1024];
  int status;

  pipe(pipe_fds);
  child = fork();
  if (!child) {
    memset(buf, sizeof(buf), 1);
    write(pipe_fds[1], buf, sizeof(buf));
    return 77;
  }

  read(pipe_fds[0], buf, big_size);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

