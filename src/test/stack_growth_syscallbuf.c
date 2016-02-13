/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int recurse(int n) {
  struct timeval tv;
  if (n <= 0) {
    return 0;
  }
  gettimeofday(&tv, NULL);
  return recurse(n - 1) + tv.tv_sec;
}

int main(void) {
  recurse(10000);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
