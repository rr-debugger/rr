/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {
}

int main(void) {
  /* 5ms */
  struct itimerval val = { { 0, 0 }, { 0, 5000 } };
  uint64_t counter = 0;
  uint64_t incr = 1;

  signal(SIGVTALRM, handler);
  setitimer(ITIMER_VIRTUAL, &val, NULL);

#ifdef __i386__
#define SP "esp"
#else
#define SP "rsp"
#endif
  for (int i = 0; i < 10000000; ++i) {
    asm("movd %0,%%xmm0\n\t"
        "movd %1,%%xmm1\n\t"
        "call 1f\n\t"
        "call 1f\n\t"
        "call 1f\n\t"
        "call 1f\n\t"
        "call 1f\n\t"
        "call 1f\n\t"
        "call 1f\n\t"
        "call 1f\n\t"
        "jmp 2f\n\t"
        /* Make sure that rr's sigframe restore doesn't overwrite our return address */
        "1: sub $4096,%%" SP "\n\t"
        "paddd %%xmm1,%%xmm0\n\t"
        "paddd %%xmm1,%%xmm0\n\t"
        "paddd %%xmm1,%%xmm0\n\t"
        "paddd %%xmm1,%%xmm0\n\t"
        "paddd %%xmm1,%%xmm0\n\t"
        "paddd %%xmm1,%%xmm0\n\t"
        "paddd %%xmm1,%%xmm0\n\t"
        "paddd %%xmm1,%%xmm0\n\t"
        "add $4096,%%" SP "\n\t"
        "ret\n\t"
        "2: movd %%xmm0,%0\n\t"
        : "=m"(counter) : "m"(incr) : "xmm0", "xmm1");
  }

  atomic_printf("counter=%lld\n", (long long)counter);
  if (counter != 640000000) {
    atomic_puts("Invalid counter");
    return 1;
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
