/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void sighandler(int sig, siginfo_t* si,
                       __attribute__((unused)) void* utp) {
  test_assert(SIGSEGV == sig && si->si_addr == (void*)0x44);

  atomic_puts("EXIT-SUCCESS");
  _exit(0);
}

int main(void) {
  struct sigaction act;

  act.sa_sigaction = sighandler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &act, NULL);

  ((void (*)(void))(0x44))();
  return 0;
}
