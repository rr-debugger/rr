/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int parent_to_child_fds[2];

int main(void) {
  pid_t child;
  char ch;
  int status;
  sigset_t sigs;

  test_assert(0 == pipe(parent_to_child_fds));

  if (0 == (child = fork())) {
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    kill(getpid(), SIGSEGV);
    return 77;
  }

  /* Try to block all signals. See if we can still get woken up. */
  sigfillset(&sigs);
  test_assert(0 == sigprocmask(SIG_SETMASK, &sigs, NULL));

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSEGV << 8) | 0x7f));

  test_assert(0 == kill(child, SIGKILL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
