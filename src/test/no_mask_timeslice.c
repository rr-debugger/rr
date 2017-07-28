/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pseudospinlock;
static pthread_barrier_t bar;

static void* thread(__attribute__((unused)) void* unused) {
  pthread_barrier_wait(&bar);

  sched_yield();
  pseudospinlock = 1;

  return NULL;
}

int main(void) {
  sigset_t old, mask;
  pthread_t t;

  pthread_barrier_init(&bar, NULL, 2);

  test_assert(0 == pthread_create(&t, NULL, thread, NULL));

  sigfillset(&mask);
  pthread_sigmask(SIG_BLOCK, &mask, &old);

  pthread_barrier_wait(&bar);
  while (!pseudospinlock) {
    ;
  }

  pthread_sigmask(SIG_SETMASK, &old, NULL);

  pthread_join(t, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
