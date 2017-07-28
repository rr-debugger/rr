/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_THREADS 10
#define NUM_TRIALS 1000

static pthread_mutex_t lock;

static void* thread(void* idp) {
  int tid = (intptr_t)idp;
  int i;

  atomic_printf("thread %d starting ...\n", tid);
  for (i = 0; i < NUM_TRIALS; ++i) {
    pthread_mutex_lock(&lock);
    sched_yield();
    pthread_mutex_unlock(&lock);
  }
  atomic_printf("  ... thread %d done.\n", tid);
  return NULL;
}

int main(void) {
  pthread_mutexattr_t attr;
  pthread_t threads[NUM_THREADS];
  int i, err;

  pthread_mutexattr_init(&attr);
  test_assert(0 == pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT));
  if ((err = pthread_mutex_init(&lock, &attr))) {
    test_assert(ENOTSUP == err);
    test_assert(0 == pthread_mutex_init(&lock, NULL));
  }

  for (i = 0; i < NUM_THREADS; ++i) {
    test_assert(0 ==
                pthread_create(&threads[i], NULL, thread, (void*)(intptr_t)i));
  }
  for (i = 0; i < NUM_THREADS; ++i) {
    test_assert(0 == pthread_join(threads[i], NULL));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
