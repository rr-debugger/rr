/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int parent_to_child_fds[2];
static pid_t child2;

static void handle_sigchld(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
  kill(child2, SIGKILL);
  exit(0);
}

int main(void) {
  pid_t child1;

  test_assert(0 == pipe(parent_to_child_fds));

  signal(SIGCHLD, handle_sigchld);

  if (0 == (child1 = fork())) {
    char ch;
    read(parent_to_child_fds[0], &ch, 1);
    kill(getpid(), SIGTERM);
    return 77;
  }

  /* while we're waiting for child2, a SIGCHLD from child1
     should still be deliverable (interrupting the wait) */
  if (0 == (child2 = fork())) {
    pause();
    return 99;
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child1, NULL, NULL));
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));

  waitpid(child2, NULL, 0);
  test_assert(0 && "Should never return");
  return 33;
}
