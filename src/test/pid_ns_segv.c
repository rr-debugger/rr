/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

int main(void) {
  pid_t pid;
  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    // We may not have permission to set up namespaces, so bail.
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  // This is the first child, therefore PID 1 in its PID namespace
  pid = fork();
  test_assert(pid >= 0);
  if (pid == 0) {
    test_assert(getpid() == 1);
    crash_null_deref();
    test_assert(0 && "Shouldn't have gotten here");
  }

  int status;
  waitpid(pid, &status, __WALL);
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
