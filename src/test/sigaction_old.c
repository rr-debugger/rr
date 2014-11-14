/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void handler1(int sig, siginfo_t* si, void* p) {}

static void handler2(int sig, siginfo_t* si, void* p) {}

static void handler3(int sig, siginfo_t* si, void* p) {}

int main(int argc, char* argv[]) {
  struct sigaction sa;
  struct sigaction old_sa;

  sa.sa_sigaction = handler1;
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
