/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  sigset_t blocked_mask;
  sigset_t unblocked_mask;

  sigemptyset(&unblocked_mask);
  sigemptyset(&blocked_mask);
  sigaddset(&blocked_mask, SIGCHLD);

  for (i = 0; i < 2000; ++i) {
    pthread_sigmask(SIG_SETMASK, &blocked_mask, NULL);
    pthread_sigmask(SIG_SETMASK, &unblocked_mask, NULL);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
