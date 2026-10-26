/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* We have rr SIGKILL the child in its signal-stop for SIGUSR1, and let it
   reach its PTRACE_EVENT_EXIT stop, before rr reads the siginfo of the
   signal-stop. */

int main(void) {
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    rr_arm_kill(RRCALL_KILL_BEFORE_GETSIGINFO, SIGUSR1, 0);
    raise(SIGUSR1);
    return 77;
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status));
  if (WTERMSIG(status) == SIGKILL) {
    atomic_puts("child was killed");
  } else {
    test_assert(WTERMSIG(status) == SIGUSR1);
    atomic_puts("child got SIGUSR1");
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
