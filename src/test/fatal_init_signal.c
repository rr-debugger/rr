/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "nsutils.h"

static char ch = 1;

int main(void) {
  pid_t pid;
  int status;
  int ret;
  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    // We may not have permission to set up namespaces, so bail.
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  // This is the first child, therefore PID 1 in its PID namespace
  pid = fork();
  test_assert(pid >= 0);
  if (pid == 0) {
    test_assert(getpid() == 1);
    // This will be nonfatal because we don't have a handler for it.
    kill(getpid(), SIGQUIT);
    // Ensure at least one tick
    if (ch == 1) {
      ch = 3;
    }
    return 55;
  }

  ret = waitpid(pid, &status, 0);
  test_assert(ret == pid);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 55);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
