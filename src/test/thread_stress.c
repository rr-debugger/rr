/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Chosen so that |3MB * THREAD_GROUPS * THREADS_PER_GROUP| exhausts a
 * 32-bit address space. */
#define THREAD_GROUPS 150
#define THREADS_PER_GROUP 10

static void* thread(__attribute__((unused)) void* unused) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return NULL;
}

int main(void) {
  int i;

  for (i = 0; i < THREAD_GROUPS; ++i) {
    pthread_t threads[THREADS_PER_GROUP];
    int j;
    for (j = 0; j < THREADS_PER_GROUP; ++j) {
      test_assert(0 == pthread_create(&threads[j], NULL, thread, NULL));
    }
    for (j = 0; j < THREADS_PER_GROUP; ++j) {
      test_assert(0 == pthread_join(threads[j], NULL));
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
