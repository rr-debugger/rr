/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#define _FILE_OFFSET_BITS 64

#include "util.h"
#include <stdlib.h>

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  breakpoint();
  return 0;
}
