/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define NUM_ITERATIONS (1 << 27)

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int spin(void) {
  int i, dummy = 0;

  atomic_puts("spinning");
  for (i = 1; i < NUM_ITERATIONS; ++i) {
    dummy += i % (1 << 20);
    dummy += i % (79 * (1 << 20));
  }
  return dummy;
}

static void* do_thread(void* p) {
  breakpoint();
  return NULL;
}

int main(int argc, char* argv[]) {
  int s = spin();
  pthread_t thread;

  pthread_create(&thread, NULL, do_thread, NULL);
  pthread_join(thread, NULL);

  atomic_printf("EXIT-SUCCESS dummy=%d\n", s);
  return 0;
}
