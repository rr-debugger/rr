/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  pid_t child;
  int status;

  test_assert(argc <= 2);
  if (argc == 2) {
    return 77;
  }

  if ((child = fork()) == 0) {
    execlp(argv[0], argv[0], "self", NULL);
    test_assert("Not reached" && 0);
  }
  sched_yield();

  /* Try sending SIGSTOP to the child while it is in exec */
  kill(child, SIGSTOP);
  kill(child, SIGCONT);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
