/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static uint64_t first;

static __attribute__((noinline)) uint64_t buffered_rdtsc(void) {
  return rdtsc();
}

void do_stuff(void) {
  uint64_t second = buffered_rdtsc();
  uint32_t third_lo;
  uint32_t third_hi;
  asm volatile ("rdtsc\n\t"
                : "=a"(third_lo), "=d"(third_hi));
  test_assert(first < second);
  test_assert(second < ((uint64_t)third_hi << 32) + third_lo);
  atomic_puts("Printed stuff OK");
}

int main(void) {
  first = buffered_rdtsc();

  /* Diversion will start here */
  breakpoint();

  do_stuff();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

