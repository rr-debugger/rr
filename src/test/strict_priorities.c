/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <sched.h>
#include <sys/types.h>
#include <unistd.h>

#define NUM_ITERATIONS (1 << 30)

static volatile int main_thread_done = 0;

static void* low_priority_func(__attribute__((unused)) void* unused) {
  setpriority(PRIO_PROCESS, 0, 4);
  /* This thread should never be scheduled again unless/until the main
     thread exits. */
  test_assert(main_thread_done);
  return NULL;
}

int main(void) {
  int i, j;
  int dummy = 0;
  pthread_t low_priority_thread;

  pthread_create(&low_priority_thread, NULL, low_priority_func, NULL);

  /* Eat some CPU and do some (nonblocking) system calls */
  for (i = 0; i < 64; ++i) {
    getpid();
    for (j = 0; j < NUM_ITERATIONS / 64; ++j) {
      dummy += j % (1 << 20);
      dummy += j % (79 * (1 << 20));
    }
  }

  /* Set this before the puts below since the puts could block */
  main_thread_done = 1;

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
