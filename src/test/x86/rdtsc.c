/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
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
    tsc = rdtsc();
    test_assert(last_tsc < tsc);
    atomic_printf("%" PRIu64 ",", tsc);
    last_tsc = tsc;
  }
  atomic_puts("");

  __rdtscp(&u);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
