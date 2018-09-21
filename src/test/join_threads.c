/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* thread(__attribute__((unused)) void* unused) {
  return NULL;
}

int main(void) {
  int i;
  pthread_t threads[100];

  for (i = 0; i < 100; ++i) {
    test_assert(0 == pthread_create(&threads[i], NULL, thread, NULL));
  }
  for (i = 0; i < 100; ++i) {
    test_assert(0 == pthread_join(threads[i], NULL));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
