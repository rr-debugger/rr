/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS (1 << 27)

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int spin(int iterations) {
  int i, dummy = 0;

  atomic_puts("spinning");
  for (i = 1; i < iterations; ++i) {
    dummy += i % (1 << 20);
    dummy += i % (79 * (1 << 20));
  }
  return dummy;
}

static void* do_thread(__attribute__((unused)) void* p) {
  breakpoint();
  return NULL;
}

int main(void) {
  int s = spin(NUM_ITERATIONS);
  pthread_t thread;

  pthread_create(&thread, NULL, do_thread, NULL);
  pthread_join(thread, NULL);

  s = spin(1000);
  atomic_printf("EXIT-SUCCESS dummy=%d\n", s);
  return 0;
}
