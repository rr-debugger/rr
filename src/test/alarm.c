/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int caught_sig = 0;

void catcher(int signum, siginfo_t* siginfo_ptr, void* ucontext_ptr) {
  caught_sig = signum;
}

int main(int argc, char** argv) {
  struct sigaction sact;
  int counter;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = 0;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

  alarm(1); /* timer will pop in 1 second */

  for (counter = 0; counter >= 0 && !caught_sig; counter++)
    if (counter % 100000 == 0)
      write(STDOUT_FILENO, ".", 1);

  atomic_printf("\nSignal %d caught, Counter is %d\n", caught_sig, counter);
  test_assert(SIGALRM == caught_sig);

  return 0;
}
