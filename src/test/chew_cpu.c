/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 1000000000

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int spin(void) {
  int i, dummy = 0;

  atomic_puts("spinning");
  /* NO SYSCALLS AFTER HERE: the point of this test is to hit
   * hpc interrupts to exercise the nonvoluntary interrupt
   * scheduler. */
  for (i = 1; i < NUM_ITERATIONS; ++i) {
    dummy += i % (1 << 20);
    dummy += i % (79 * (1 << 20));
    if (i == NUM_ITERATIONS / 2) {
      breakpoint();
    }
  }
  return dummy;
}

int main(void) {
  atomic_printf("EXIT-SUCCESS dummy=%d\n", spin());
  return 0;
}
