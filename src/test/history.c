/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpointA(__attribute__((unused)) int i) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  int i;
  for (i = 0; i < 5; ++i) {
    breakpointA(i);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
