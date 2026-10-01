/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#ifdef __RR_SOFTTICKS__
#include <rr/softticks.h>
#endif

static void breakpoint(void) {}

static volatile int caught_sig = 0;

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = signum;
}

int main(void) {
  struct sigaction sact;
  long counter = 0;
  long counter2 = 0;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

#if defined(RR_SOFTTICKS_TICK_ASM) && (defined(__x86_64__) || defined(__i386__))
  /* Built for software ticks there is no branch counter to overflow, and the loop below
     has no ticks: replay could only find where the signal arrived by stopping at every
     iteration. Test the software counterpart instead: first tick well past 2^32 (rr
     arms at most 2^32-1 ticks at a time, so this takes several stops), deterministically
     (the compiler ticks this loop), then let the signal arrive in a loop that ticks. */
  for (long long i = 0; i < (1LL << 32) + (1LL << 28); ++i) {
    asm volatile("" : : : "memory");
  }
  alarm(1);
#ifdef __x86_64__
  asm("2: " RR_SOFTTICKS_TICK_ASM "\n\t"
      "incq %0\n\t"
      "cmpl $0,%1\n\t"
      "je 2b\n\t"
      : "+r"(counter)
      : "m"(caught_sig)
      : "cc");
#else
  asm("2: " RR_SOFTTICKS_TICK_ASM "\n\t"
      "incl %0\n\t"
      "adcl $0,%1\n\t"
      "cmpl $0,%2\n\t"
      "je 2b\n\t"
      : "+r"(counter), "+r"(counter2)
      : "m"(caught_sig)
      : "cc");
#endif
#else
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
#elif defined(__aarch64__)
  register long tmp = 0;
  asm("1: add %0, %0, #1\n\t"
      "ldr %1, %2\n\t"
      "cmp %w1, %w0\n\t"
      "bne 1b" : "+r"(counter) : "r"(tmp), "m"(caught_sig));
#else
#error Unknown architecture
#endif
#endif

  atomic_printf("Signal %d caught, Counter is %lld\n", caught_sig,
                counter + (((long long)counter2) << 32));
  test_assert(SIGALRM == caught_sig);

  breakpoint();

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
