/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static pthread_cond_t condvar = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex;

static void* start_thread(__attribute__((unused)) void* p) {
  while (1) {
    sched_yield();
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&condvar);
    pthread_mutex_unlock(&mutex);
  }
  return NULL;
}

int main(void) {
  pthread_mutexattr_t attr;
  pthread_t thread;

  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init(&mutex, &attr);

  pthread_create(&thread, NULL, start_thread, NULL);

  pthread_mutex_lock(&mutex);
  pthread_cond_wait(&condvar, &mutex);
  pthread_cond_wait(&condvar, &mutex);
  pthread_mutex_unlock(&mutex);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
