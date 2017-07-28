/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

pthread_barrier_t bar;

static void* thread(__attribute__((unused)) void* unused) {
  pthread_barrier_wait(&bar);

  sleep(-1);
  return NULL;
}

int main(void) {
  pthread_t t;

  pthread_barrier_init(&bar, NULL, 2);

  pthread_create(&t, NULL, thread, NULL);

  pthread_barrier_wait(&bar);

  atomic_puts("_exit()ing");

  _exit(0);
  return 0; /* not reached */
}
