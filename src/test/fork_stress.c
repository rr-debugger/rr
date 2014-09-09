/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define NUM_ITERATIONS 250

int main(int argc, char* argv[]) {
  int i;

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    if (0 == fork()) {
      return 0;
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
