/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];

int main(void) {
  char buf;
  pid_t pid;
  int status;
  sigset_t mask;

  test_assert(0 == pipe(pipe_fds));

  sigemptyset(&mask);
  sigfillset(&mask);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));

  /* Check that even when all signals are supposedly blocked,
     syscallbuf still works */
  pid = fork();
  if (!pid) {
    test_assert(1 == write(pipe_fds[1], "y", 1));
    return 77;
  }
  test_assert(1 == read(pipe_fds[0], &buf, 1));
  test_assert(pid == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
