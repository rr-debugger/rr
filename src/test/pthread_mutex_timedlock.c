/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pthread_mutexattr_t attr;
  pthread_mutex_t mutex;
  struct timespec abstime = {};

  pthread_mutexattr_init(&attr);
  pthread_mutex_init(&mutex, &attr);

  pthread_mutex_timedlock(&mutex, &abstime);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
