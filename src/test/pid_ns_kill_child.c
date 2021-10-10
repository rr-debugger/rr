/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

int main(void) {
  pid_t pid;
  int pipe_fds[2];
  char ch;
  pipe(pipe_fds);

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  signal(SIGTERM, SIG_IGN);
  /* Print this now because we will get killed */
  atomic_puts("EXIT-SUCCESS");

  /* This is the first child, therefore PID 1 in its PID namespace */
  pid = fork();
  test_assert(pid >= 0);
  if (!pid) {
    int i;
    for (i = 0; i < 20; ++i) {
      pid = fork();
      if (!pid) {
        /* The grandchild just sleeps */
        pause();
      }
      test_assert(pid == i + 2);
    }
    write(pipe_fds[1], "x", 1);
    pause();
  }

  read(pipe_fds[0], &ch, 1);

  return 0;
}
