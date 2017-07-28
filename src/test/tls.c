/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

__thread int tlsvar;

void breakpoint_fn(void) {}

void* thread_fn(void* arg) {
  tlsvar = *(int*)arg;
  breakpoint_fn();
  return NULL;
}

int main(void) {
  pthread_t thread;

  int value = 97;
  pthread_create(&thread, NULL, thread_fn, &value);
  pthread_join(thread, NULL);

  return 0;
}
