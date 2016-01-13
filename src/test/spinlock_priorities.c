/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static volatile int low_priority_thread_scheduled = 0;

static void* low_priority_thread(__attribute__((unused)) void* p) {
  setpriority(PRIO_PROCESS, 0, 4);

  __sync_val_compare_and_swap(&low_priority_thread_scheduled, 0, 1);

  return NULL;
}

int main(void) {
  pthread_t thread;

  pthread_create(&thread, NULL, low_priority_thread, NULL);

  test_assert(!low_priority_thread_scheduled);

  while (__sync_val_compare_and_swap(&low_priority_thread_scheduled, 1, 0) ==
         0) {
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
