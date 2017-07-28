/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static int var;

int main(void) {
  int i;

  for (i = 0; i < 5000; ++i) {
    ++var;
    breakpoint();
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
