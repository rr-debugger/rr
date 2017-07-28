/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int parent_to_child_fds[2];
static int child_to_parent_fds[2];

int main(void) {

  pid_t child;
  char ch;
  int status;

  test_assert(0 == pipe(parent_to_child_fds));
  test_assert(0 == pipe(child_to_parent_fds));

  if (0 == (child = fork())) {
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, 0, 0));
    test_assert(-1 == ptrace(PTRACE_TRACEME, 0, 0, 0));
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    test_assert(1 == write(child_to_parent_fds[1], "x", 1));
    raise(SIGSTOP);
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    return 0;
  }

  /* Make sure child is still running */
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));
  test_assert(1 == read(child_to_parent_fds[0], &ch, 1));

  /* Wait until the tracee stops */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  /* Ask for a ptrace notification on exit */
  test_assert(0 == ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEEXIT));
  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));

  test_assert(1 == write(parent_to_child_fds[1], "p", 1));

  /* Child is now exiting. Check for the PTRACE_EVENT_EXIT notification */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)));

  ptrace(PTRACE_CONT, child, 0, 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
