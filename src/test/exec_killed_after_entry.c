/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* rr SIGKILLs the child once it has handled the syscall-entry stop of the
   child's execve, and waits for the child's PTRACE_EVENT_EXIT stop without
   collecting it, so rr finds that stop when it resumes the child into the
   execve. rr must handle the child's exit while the execve is in
   progress. */

int main(int argc, char** argv) {
  pid_t child;
  int status;
  int armed;

  if (argc > 1) {
    return 0;
  }

  armed = rr_arm_kill(RRCALL_KILL_AFTER_EXEC_ENTRY, 0,
                      RRCALL_ARM_KILL_INHERIT);
  child = fork();
  test_assert(child >= 0);
  if (!child) {
    char* args[] = { argv[0], "child", NULL };
    execve(argv[0], args, environ);
    test_assert(0 && "Failed exec!");
  }
  test_assert(child == waitpid(child, &status, 0));
  if (armed) {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
