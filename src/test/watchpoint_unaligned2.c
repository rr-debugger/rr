/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct {
  uint32_t low;
  uint32_t high;
} value;

int main(void) {
  // -O3 should consolidate these into a single store.
  value.low = 1;
  value.high = 2;

  // This will fail; we just want the compiler to not optimize out
  // the store.
  test_assert(-1 == write(-1, &value, sizeof(value)));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
