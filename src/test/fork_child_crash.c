/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  pid_t child = fork();
  int status;

  if (0 == child) {
    atomic_printf("child %d\n", getpid());

    breakpoint();

    atomic_puts("subprocess: crashing ...");
    *(volatile int*)NULL = 0;
    exit(0); /* not reached */
  }

  test_assert(child == waitpid(child, &status, 0));
  atomic_printf("parent: subprocess %d exited with %#x\n", child, status);
  test_assert(WIFSIGNALED(status) && SIGSEGV == WTERMSIG(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
