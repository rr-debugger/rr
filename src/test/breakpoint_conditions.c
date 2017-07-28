/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpointA(__attribute__((unused)) int v4) {
  int break_here = 1;
  (void)break_here;
}

static void breakpointB(__attribute__((unused)) int v4) {
  int break_here = 1;
  (void)break_here;
}

int v0 = 0;
int v1 = 1;
int v2 = 2;
int v3 = 3;
int vm1 = -1;
int vm2 = -2;
uint64_t u64max = (uint64_t)(int64_t)-1;
int* p = (int*)&u64max;

int main(void) {
  int i;
  for (i = 0; i < 10000; ++i) {
    breakpointA(4);
    breakpointB(4);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
