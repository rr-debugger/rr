/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

static int flag;
static pthread_mutex_t mutex;

static void* run_thread(__attribute__((unused)) void* p) {
  pthread_mutex_lock(&mutex);
  pthread_mutex_unlock(&mutex);
  flag = 1;
  return NULL;
}

int main(__attribute__((unused)) int argc) {
  int i;
  pthread_t thread;
  struct timespec ts = { 0, 10000000 };

  pthread_mutex_init(&mutex, NULL);
  pthread_mutex_lock(&mutex);
  pthread_create(&thread, NULL, run_thread, NULL);
  nanosleep(&ts, NULL);
  pthread_mutex_unlock(&mutex);
  if (flag > 0) {
    caught_test_failure("flag set");
  }
  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
