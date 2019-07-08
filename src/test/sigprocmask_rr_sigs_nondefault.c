/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  sigset_t mask, oldmask;
  int err;

  sigfillset(&mask);
  /* Since we passed --syscall-buffer-sig=SIGPROF, SIGPROF is now used
   * internally by rr, and we won't be able to turn it off.
   * rr shouldn't observably change `mask` when it does this though */
  err = sigprocmask(SIG_BLOCK, &mask, &oldmask);
  test_assert(err == 0);

  test_assert(sigismember(&mask, SIGPROF) == 1);

  /* But SIGPWR should be usable now */
  raise(SIGPWR);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
