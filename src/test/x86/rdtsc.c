/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static uint64_t my_rdtsc(void) {
  uint32_t low;
  uint32_t high;
  /* Make sure this doesn't get buffered */
  asm ("rdtsc_instruction: rdtsc; xchg %%edx,%%edx" : "=a"(low), "=d"(high));
  return ((uint64_t)high << 32) + low;
}

int main(void) {
  int i;
  unsigned int u;
  uint64_t last_tsc = 0;

  for (i = 0; i < 100; ++i) {
    uint64_t tsc;

    breakpoint();
    /* NO SYSCALLS BETWEEN HERE AND RDTSC: next event for
     * replay must be rdtsc */
    tsc = my_rdtsc();
    test_assert(last_tsc < tsc);
    atomic_printf("%" PRIu64 ",", tsc);
    last_tsc = tsc;
  }
  atomic_puts("");

  __rdtscp(&u);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
