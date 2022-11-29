/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct {
  uint32_t low;
  uint32_t high;
} value;

static void breakpoint(void) {
  // Put something in here so the optimizer can't eat this function.
  atomic_puts(".");
}

int main(void) {
  breakpoint();

  // -O3 should consolidate these into a single load.
  value.low = 1;
  value.high = 2;

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
