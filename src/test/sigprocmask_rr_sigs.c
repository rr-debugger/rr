/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  sigset_t mask, oldmask;
  int err;

  sigfillset(&mask);
  /* SIGPWR is used internally by rr, and we won't be able to turn it off.
     rr shouldn't observably change `mask` when it does this though */
  err = sigprocmask(SIG_BLOCK, &mask, &oldmask);
  test_assert(err == 0);

  test_assert(sigismember(&mask, SIGPWR) == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
