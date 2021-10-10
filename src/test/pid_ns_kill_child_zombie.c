/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#define NUM_GRANDCHILDREN 5

int main(void) {
  pid_t pid;
  int pipe_fds[2];
  int i;
  char ch;
  pipe(pipe_fds);

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  /* This is the first child, therefore PID 1 in its PID namespace.
     Spawn some grandchildren that just hang. */
  pid = fork();
  test_assert(pid >= 0);
  if (!pid) {
    for (i = 0; i < NUM_GRANDCHILDREN; ++i) {
      pid = fork();
      test_assert(pid >= 0);
      if (!pid) {
        pause();
        return 0;
      }
      test_assert(pid == i + 2);
    }
    write(pipe_fds[1], "x", 1);
    pause();
  }

  read(pipe_fds[0], &ch, 1);

  atomic_puts("EXIT-SUCCESS");
  /* Now kill the pid-ns init process. This will move it to its exit stop. */
  kill(pid, SIGKILL);
  /* When we exit, rr will do Task::kill() on the pid-ns init process.
     This will reach zap_pid_ns_processes to kill the grandchildren.
     rr needs to handle this without deadlocking. */

  return 0;
}
