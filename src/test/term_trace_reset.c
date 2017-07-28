/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

volatile int dummy;

int main(void) {
  int i = 0;

  atomic_puts("ready");
  atomic_puts("EXIT-SUCCESS");

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  while (1) {
    dummy += i % (1 << 20);
    dummy += i % (79 * (1 << 20));
  }

  return 0;
}
