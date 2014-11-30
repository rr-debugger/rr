/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

void catcher(int signum, siginfo_t* siginfo_ptr, void* ucontext_ptr) {
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

int main(int argc, char** argv) {
  struct sigaction sact;
  int r = 0;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

  alarm(1); /* timer will pop in 1 second */

  sleep(10);

  return r;
}
