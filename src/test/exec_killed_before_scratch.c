/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* We have rr SIGKILL the child after its exec, just before rr maps its
   scratch memory, before the new image runs. */

int main(int argc, char** argv) {
  pid_t child;
  int status;
  sigset_t set;

  if (argc > 1) {
    return 0;
  }

  /* With SIGTRAP blocked (the child inherits that, and it survives the exec),
     rr runs its remote syscalls in the child with PTRACE_SYSCALL rather than
     single-stepping, so the child is never in a SIGTRAP
     signal-delivery-stop when rr kills it. Before Linux 5.17 (kernel commit
     b171f667f378) a SIGKILL there doesn't leave the task in a
     PTRACE_EVENT_EXIT stop that rr can see. */
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));

  child = fork();
  if (!child) {
    char* args[] = { argv[0], "child", NULL };
    rr_arm_kill(RRCALL_KILL_BEFORE_EXEC_SCRATCH, 0, 0);
    execve(argv[0], args, environ);
    test_assert(0 && "Failed exec!");
  }
  test_assert(child == waitpid(child, &status, 0));
  if (WIFSIGNALED(status)) {
    test_assert(WTERMSIG(status) == SIGKILL);
    atomic_puts("child was killed");
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    atomic_puts("child exited");
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
