/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

extern int cpuid_loop(int iterations);

int main(void) {
  int sum;
  getegid();
  sum = cpuid_loop(1000);
  atomic_printf("EXIT-SUCCESS; sum=%d\n", sum);
  return 0;
}
