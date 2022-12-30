/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void do_rdtsc(void) {
  asm("rdtsc");
}

int main(void) {
  int i;
  for (i = 0; i < 2000000; ++i) {
    do_rdtsc();
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
