/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Our child arms RRCALL_KILL_AFTER_EXEC_STOP with RRCALL_ARM_KILL_INHERIT
   and creates two children of its own, which get copies of the arming. Once
   both exist, they exec, and rr kills each of them once it has handled its
   PTRACE_EVENT_EXEC stop. Then our child execs too, and rr kills it as well:
   killing the others didn't disarm it. We didn't arm anything, so we run
   normally. */

static void exec_self(char* exe) {
  char* argv[] = { exe, "exec'd", NULL };
  execve(exe, argv, environ);
  test_assert(0 && "Failed exec!");
}

static void check_status(pid_t child, int killed) {
  int status;
  test_assert(child == waitpid(child, &status, 0));
  if (killed) {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
}

static void run_armed(char* exe) {
  int armed =
      rr_arm_kill(RRCALL_KILL_AFTER_EXEC_STOP, 0, RRCALL_ARM_KILL_INHERIT);
  int fds[2];
  pid_t children[2];
  char ch;
  int i;

  test_assert(0 == pipe(fds));
  for (i = 0; i < 2; ++i) {
    children[i] = fork();
    if (!children[i]) {
      /* Wait until both children exist. */
      test_assert(0 == close(fds[1]));
      test_assert(0 == read(fds[0], &ch, 1));
      exec_self(exe);
    }
    test_assert(children[i] > 0);
  }
  test_assert(0 == close(fds[1]));
  for (i = 0; i < 2; ++i) {
    check_status(children[i], armed);
  }
  exec_self(exe);
}

int main(int argc, char** argv) {
  int under_rr;
  pid_t child;

  if (argc > 1) {
    return 0;
  }

  /* This only tells us whether rr is running. */
  under_rr = rr_arm_kill(RRCALL_KILL_NONE, 0, 0);

  child = fork();
  if (!child) {
    run_armed(argv[0]);
  }
  test_assert(child > 0);
  check_status(child, under_rr);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
