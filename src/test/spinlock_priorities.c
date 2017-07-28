/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int low_priority_thread_scheduled = 0;

static int low_to_high[2];
static int high_to_low[2];

static void* low_priority_thread(__attribute__((unused)) void* p) {
  char ch;

  setpriority(PRIO_PROCESS, 0, 4);

  test_assert(1 == write(low_to_high[1], "x", 1));
  test_assert(1 == read(high_to_low[0], &ch, 1));

  __sync_val_compare_and_swap(&low_priority_thread_scheduled, 0, 1);

  return NULL;
}

int main(void) {
  pthread_t thread;
  char ch;

  test_assert(0 == pipe(low_to_high));
  test_assert(0 == pipe(high_to_low));

  pthread_create(&thread, NULL, low_priority_thread, NULL);

  test_assert(1 == read(low_to_high[0], &ch, 1));
  test_assert(1 == write(high_to_low[1], "y", 1));

  test_assert(!low_priority_thread_scheduled);

  while (__sync_val_compare_and_swap(&low_priority_thread_scheduled, 1, 0) ==
         0) {
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
