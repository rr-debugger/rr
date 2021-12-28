/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static pthread_key_t exit_key;
static uint64_t exit_key_value;

static void thread_exit(__attribute__((unused)) void* data) {
  atomic_puts("thread exit");
}

static void* thread(__attribute__((unused)) void* unused) {
  pthread_key_create(&exit_key, thread_exit);
  pthread_setspecific(exit_key, (void*)&exit_key_value);
  pthread_exit(NULL);
}

int main(void) {
  pthread_t t;

  pthread_create(&t, NULL, thread, NULL);
  pthread_join(t, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
