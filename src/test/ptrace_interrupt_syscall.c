/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 1000

static int fds[2];

int main(void) {
  pid_t child;
  int status;
  int i;
  char ch;

  test_assert(0 == pipe(fds));

  if (0 == (child = fork())) {
    test_assert(1 == read(fds[0], &ch, 1));
    return 77;
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    /* Interrupt the child while it's blocked in read(), and resume it. */
    wait_for_task_asleep_in_syscall(child, SYS_read, fds[0]);
    test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
    test_assert(child == waitpid(child, &status, 0));
    /* Linux reports a PTRACE_EVENT_STOP with SIGTRAP here, but rr doesn't
       emulate that exactly. */
    test_assert(WIFSTOPPED(status));
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  }

  test_assert(1 == write(fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
