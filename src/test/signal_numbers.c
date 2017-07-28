/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int sig;

  for (sig = 1; sig <= 64; ++sig) {
    struct sigaction sa;

    /* Skip signals that are fatal and can't be ignored, and skip
       signals that rr uses for itself. */
    if (sig == SIGKILL || sig == SIGSTOP || sig == SIGSTKFLT || sig == SIGPWR) {
      continue;
    }

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sa.sa_restorer = NULL;
    sigemptyset(&sa.sa_mask);
    /* Avoid libc wrappers since glibc won't let us send certain signals that
       it reserves for itself */
    test_assert(0 == syscall(SYS_rt_sigaction, sig, &sa, NULL, 8));
    test_assert(0 == kill(getpid(), sig));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
