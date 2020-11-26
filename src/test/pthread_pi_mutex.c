/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pthread_mutexattr_t attr;
  pthread_mutex_t mutex;

  test_assert(pthread_mutexattr_init(&attr) == 0);
  test_assert(pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT) == 0);
  test_assert(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
  test_assert(pthread_mutex_init(&mutex, &attr) == 0);
  test_assert(pthread_mutex_destroy(&mutex) == 0);
  test_assert(pthread_mutexattr_destroy(&attr) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
