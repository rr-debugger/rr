/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS (1 << 27)

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static int spin(void) {
  int i, dummy = 0;

  atomic_puts("spinning");
  for (i = 1; i < 1 << 28; ++i) {
    dummy += i % (1 << 20);
    dummy += i % (79 * (1 << 20));
  }
  return dummy;
}

/**
 * We'll break in do_thread, continue until SIGKILL, and
 * then try a reverse-stepi. This will have to search back through
 * several checkpoints to find the last completed singlestep for
 * the thread.
 */
static void* do_thread(__attribute__((unused)) void* p) {
  char ch;
  breakpoint();
  /* Will never return */
  read(STDIN_FILENO, &ch, 1);
  return NULL;
}

int main(void) {
  pthread_t thread;

  pthread_create(&thread, NULL, do_thread, NULL);

  spin();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
