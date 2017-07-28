/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {}

static volatile int caught_sig = 0;

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = signum;
}

int main(void) {
  struct sigaction sact;
  int counter;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

  alarm(1); /* timer will pop in 1 second */

  for (counter = 0; counter >= 0 && !caught_sig; counter++) {
    if (counter % 100000 == 0) {
      write(STDOUT_FILENO, ".", 1);
    }
  }

  atomic_printf("\nSignal %d caught, Counter is %d\n", caught_sig, counter);
  test_assert(SIGALRM == caught_sig);

  breakpoint();

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
