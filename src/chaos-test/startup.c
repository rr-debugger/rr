/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

static int flag;
static pthread_mutex_t mutex;

static void* run_thread(__attribute__((unused)) void* p) {
  struct timespec ts = { 1, 0 };
  nanosleep(&ts, NULL);
  pthread_mutex_lock(&mutex);
  flag = 1;
  pthread_mutex_unlock(&mutex);
  return NULL;
}

int main(void) {
  int i;
  pthread_t thread;

  pthread_mutex_init(&mutex, NULL);
  pthread_create(&thread, NULL, run_thread, NULL);
  pthread_mutex_lock(&mutex);
  if (flag > 0) {
    caught_test_failure("flag set");
  }
  pthread_mutex_unlock(&mutex);
  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
