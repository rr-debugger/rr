/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void start_test(void) {
  int break_here = 1;
  (void)break_here;
}

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  // glibc write() might only be patched after the first time it is executed.
  atomic_puts("Ensure glibc write() is patched...");

  start_test();
  // The test requires this write() be buffered:
  atomic_puts("EXIT-SUCCESS");
  breakpoint();
  return 0;
}
