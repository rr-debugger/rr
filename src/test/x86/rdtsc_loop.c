/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
#ifdef __x86_64__
  int i;

  uint64_t prev_tsc = 0;
  for (i = 0; i < 5000000; ++i) {
    uint32_t out;
    uint32_t out_hi;
    asm volatile ("rdtsc\n\t"
                  "mov %%rax,%%rcx\n\t"
                  : "=c"(out), "=d"(out_hi)
                  :: "rax");
    uint64_t tsc = ((uint64_t)out_hi << 32) + out;
    test_assert(prev_tsc < tsc || tsc < 1000000000);
    prev_tsc = tsc;
  }
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
