/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  /* Descendant process will write one byte to the pipe to signal that it's
   * complete */
  int pipe_fds[2];
  int err = pipe(pipe_fds);
  pid_t child_pid, grandchild_pid, greatgrandchild_pid, dyingchild_pid;
  test_assert(err == 0);

  child_pid = fork();
  if (child_pid) {
    char buf;
    int n = read(pipe_fds[0], &buf, 1);
    test_assert(n == 1);
    return 0;
  }

  /* In child */
  dyingchild_pid = getpid();
  grandchild_pid = fork();
  if (grandchild_pid) {
    exit(0);
  }

  /* In grandchild */
  /* Wait for parent to die */
  while (getppid() == dyingchild_pid) {
    sched_yield();
  }

  /* Now the rr supervisor process is no longer our ancestor in the process
     tree.
     Try forking again. */
  greatgrandchild_pid = fork();
  if (greatgrandchild_pid) {
    exit(0);
  }

  /* In great-grandchild */
  atomic_puts("EXIT-SUCCESS");
  write(pipe_fds[1], "a", 1);
  return 0;
}
