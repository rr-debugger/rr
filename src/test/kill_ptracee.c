/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t child;
  int status;

  /* Just an always runnable task */
  if (0 == fork()) {
    for (;;) {
      sched_yield();
    }
  }

  if (0 == (child = fork())) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    for (;;) {
      __asm__("pause");
    }
    test_assert(0 && "Should have died");
  }

  /* Wait until the tracee stops */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  /* Continue the tracee */
  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));

  sched_yield();

  /* One or more of these may fail (since the tracee may already be dead).
   * That's ok, but nothing should assert in rr, etc.
   */

  ptrace(PTRACE_KILL, child, 0, 0);
  kill(child, SIGKILL);
  /* Not necessary for functionality, but some real applications do this, so
   * make sure we handle it fine
   */
  ptrace(PTRACE_CONT, child, 0, 0);

  /* Wait until the tracee exits */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  /* Same thing again but will while the tracee is still in the ptrace stop */
  if (0 == (child = fork())) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    test_assert(0 && "Should have died");
  }

  /* Wait until the tracee stops */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  kill(child, SIGKILL);
  ptrace(PTRACE_KILL, child, 0, 0);
  ptrace(PTRACE_CONT, child, 0, 0);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
