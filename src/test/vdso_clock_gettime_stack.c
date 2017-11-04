/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  struct timespec ts;
  for (i = 0; i < 10000; ++i) {
    clock_gettime(CLOCK_MONOTONIC, &ts);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
