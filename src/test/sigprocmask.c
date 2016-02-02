/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int signals_unblocked;

static void handle_usr1(__attribute__((unused)) int sig) {
  atomic_puts("Caught usr1");
  test_assert(signals_unblocked);
}

int main(void) {
  sigset_t mask, oldmask;
  int i, dummy = 0;

  signal(SIGUSR1, handle_usr1);

  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  /* The libc function invokes rt_sigprocmask. */
  sigprocmask(SIG_BLOCK, &mask, &oldmask);

  raise(SIGUSR1);

  for (i = 0; i < 1 << 25; ++i) {
    dummy += (dummy + i) % 9735;
  }

  signals_unblocked = 1;
/* Some systems only have rt_sigprocmask. */
#if defined(SYS_sigprocmask)
  syscall(SYS_sigprocmask, SIG_SETMASK, &oldmask, NULL);
#else
  sigprocmask(SIG_SETMASK, &oldmask, NULL);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
