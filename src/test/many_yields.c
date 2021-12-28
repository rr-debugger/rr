/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int stop;

static void* do_thread(__attribute__((unused)) void* p) {
  while (!stop) {
    sched_yield();
  }
  return NULL;
}

int main(void) {
  pthread_t thread;
  int count;
  pthread_create(&thread, NULL, do_thread, NULL);
  for (count = 0; count < 1000; ++count) {
    sched_yield();
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
