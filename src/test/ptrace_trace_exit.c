/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int parent_to_child_fds[2];

int main(void) {
  pid_t child;
  char ch;
  int status;
  struct user_regs_struct regs;

  test_assert(0 == pipe(parent_to_child_fds));

  if (0 == (child = fork())) {
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    return 77;
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD)));
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
