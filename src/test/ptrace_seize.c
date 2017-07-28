/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

static int parent_to_child_fds[2];
static int child_to_parent_fds[2];

int main(void) {
  pid_t child;
  char ch;
  int status;

  test_assert(0 == pipe(parent_to_child_fds));
  test_assert(0 == pipe(child_to_parent_fds));

  if (0 == (child = fork())) {
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    test_assert(1 == write(child_to_parent_fds[1], "x", 1));
    sleep(10000);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  /* Make sure child is still running */
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));
  test_assert(1 == read(child_to_parent_fds[0], &ch, 1));

  /* Stop it */
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));

  test_assert(0 == kill(child, SIGKILL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
