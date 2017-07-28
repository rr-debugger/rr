/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int spin(int iterations) {
  int i, dummy = 0;

  atomic_puts("spinning");
  for (i = 1; i < iterations; ++i) {
    dummy += i % (1 << 20);
    dummy += i % (79 * (1 << 20));
  }
  return dummy;
}

static int ran_thread = 0;

static void* do_thread(__attribute__((unused)) void* p) {
  ran_thread = 1;
  return NULL;
}

int main(void) {
  pthread_t t;

  pthread_create(&t, NULL, do_thread, NULL);

  spin(1 << 28);

  test_assert(ran_thread);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
