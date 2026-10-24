/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* For each step of rr's preparation of a task's exit (see
   RRCALL_KILL_IN_EXIT_PREPARATION), we have rr SIGKILL a child at that step
   of its exit(), and another at that step of its exit_group(). */

int main(void) {
  /* This arms nothing; it tells us whether we're running under rr. */
  int under_rr = rr_arm_kill(RRCALL_KILL_NONE, 0, 0);
  int step;
  int use_exit_group;

  for (step = 1; step <= 3; ++step) {
    for (use_exit_group = 0; use_exit_group <= 1; ++use_exit_group) {
      int status;
      pid_t child = fork();
      if (!child) {
        rr_arm_kill(RRCALL_KILL_IN_EXIT_PREPARATION, step, 0);
        syscall(use_exit_group ? SYS_exit_group : SYS_exit, 0);
        test_assert(0 && "exit returned");
      }
      test_assert(child == waitpid(child, &status, 0));
      if (under_rr) {
        test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
      } else {
        test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
      }
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
