/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler1(__attribute__((unused)) int sig,
                     __attribute__((unused)) siginfo_t* si,
                     __attribute__((unused)) void* p) {}

static void handler2(__attribute__((unused)) int sig,
                     __attribute__((unused)) siginfo_t* si,
                     __attribute__((unused)) void* p) {}

static void handler3(__attribute__((unused)) int sig,
                     __attribute__((unused)) siginfo_t* si,
                     __attribute__((unused)) void* p) {}

int main(void) {
  struct sigaction sa;
  struct sigaction old_sa;

  sa.sa_sigaction = handler1;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGUSR1, &sa, NULL);

  sa.sa_sigaction = handler2;
  old_sa.sa_sigaction = handler3;
  sigaction(SIGUSR1, &sa, &old_sa);
  test_assert(old_sa.sa_sigaction == handler1);

  sigaction(SIGUSR1, NULL, &old_sa);
  test_assert(old_sa.sa_sigaction == handler2);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
