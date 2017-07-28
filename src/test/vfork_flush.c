/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void unblock_signals(void) {
  sigset_t mask;
  sigemptyset(&mask);
  sigprocmask(SIG_SETMASK, &mask, NULL);
}

int main(void) {
  pid_t child;
  int status;

  if (0 == (child = vfork())) {
    /* Unblocking SIGSYS should be OK */
    unblock_signals();
    test_assert(0 == close(0));
    _exit(77);
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  /* Unblocking SIGSYS should be OK */
  unblock_signals();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
