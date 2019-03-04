/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 1000000

static void cpuid(void) {
  int eax, ebx, ecx, edx;
  asm volatile("cpuid"
               : "=a"(eax), "=b"(ebx), "=c"(ecx),
                 "=d"(edx)
               : "a"(0));
}

int spin(void) {
  int i, dummy = 0;

  /* NO SYSCALLS AFTER HERE: the point of this test is to hit
   * hpc interrupts to exercise the nonvoluntary interrupt
   * scheduler with some CPUID instructions in the mix. */
  for (i = 1; i < NUM_ITERATIONS; ++i) {
    dummy += i % (1 << 20);
    dummy += i % (79 * (1 << 20));
    if (i%1000 == 0) {
      cpuid();
    }
  }
  return dummy;
}

static void* do_thread(__attribute__((unused)) void* p) {
  spin();
  return NULL;
}

int main(void) {
  pthread_t thread;
  pthread_create(&thread, NULL, do_thread, NULL);
  spin();
  pthread_join(thread, NULL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
