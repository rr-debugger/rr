/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t child = fork();
  int status;

  if (!child) {
    int pipe_fds[2];

    test_assert(0 == pipe(pipe_fds));
    test_assert(0 == close(pipe_fds[0]));

    /* Trigger a SIGPIPE inside the syscallbuf.
       The signal will have to be deferred until the
       syscallbuf has returned. */
    write(pipe_fds[1], "x", 1);
    test_assert(0 && "Should not reach here");
    return 0;
  }

  test_assert(child == wait(&status));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
