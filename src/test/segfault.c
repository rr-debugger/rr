/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void sighandler(int sig) {
  atomic_printf("caught signal %d, exiting\n", sig);
  _exit(0);
}

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  signal(SIGSEGV, sighandler);

  breakpoint();
  /* NO SYSCALLS BETWEEN HERE AND SEGFAULT BELOW: next event to
   * replay must be the signal. */

  *((volatile int*)0) = 0;
  return 0;
}
