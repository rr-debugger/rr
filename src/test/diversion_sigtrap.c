/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static __attribute__((noinline)) int hardware_breakpoint(void) {
  asm("int3;");
  return 10;
}

int main(void) {
  breakpoint();
  hardware_breakpoint();
}
