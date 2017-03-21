/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void breakpoint(void) {}

static volatile int caught_sig = 0;

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = signum;
}

int main(void) {
  struct sigaction sact;
  long long counter = 0;
  long long counter2 = 0;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

  /* Run loop for 1 second. On my laptop, 1 second is easily enough to
     get over 2^31 conditional branches on x86-64 and x86-32, with
     the optimized code below. */
  alarm(1);

#ifdef __x86_64__
  asm("1: incq %0\n\t"
      "cmpl $0,%1\n\t"
      "je 1b\n\t"
      : "+r"(counter)
      : "m"(caught_sig));
#elif __i386__
  asm("1: incl %0\n\t"
      "adcl $0,%1\n\t"
      "cmpl $0,%2\n\t"
      "je 1b\n\t"
      : "+r"(counter), "+r"(counter2)
      : "m"(caught_sig));
#else
#error Unknown architecture
#endif

  atomic_printf("Signal %d caught, Counter is %lld\n", caught_sig,
                counter + (counter2 << 32));
  test_assert(SIGALRM == caught_sig);

  breakpoint();

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
