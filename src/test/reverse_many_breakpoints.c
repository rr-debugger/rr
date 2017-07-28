/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {}

int main(void) {
  int i;
  int result = 0;
  for (i = 0; i < 100000; ++i) {
    result += i * i;
    breakpoint();
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
