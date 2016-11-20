/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int lock;
static int accumulator = 9999;

static void hle_abort(void) {
  int j;
#if defined(__x86_64__) || defined(__i386__)
  asm("xacquire; lock addl $1,%0\n\t" : : "m"(lock));
#else
#error Unknown architecture
#endif
  /* Execute some conditional branches */
  for (j = 0; j < 10; ++j) {
    if ((accumulator % 2) == 0) {
      accumulator /= 2;
    } else {
      accumulator = accumulator * 3 + 1;
    }
  }
  /* Force abort */
  sched_yield();
#if defined(__x86_64__) || defined(__i386__)
  asm("xrelease; lock subl $1,%0\n\t" : : "m"(lock));
#else
#error Unknown architecture
#endif
}

int main(void) {
  int i;
  sched_yield();
  for (i = 0; i < 1000; ++i) {
    hle_abort();
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
