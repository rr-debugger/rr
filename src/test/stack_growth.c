/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int v = 0;

static void breakpoint(void) {}

static void funcall(void) {
  char buf[2000000];
  size_t i;
  breakpoint();
  for (i = 0; i < sizeof(buf); ++i) {
    buf[i] = (char)i;
  }
  for (i = 0; i < sizeof(buf); ++i) {
    v += buf[i % 777777];
  }
}

int main(void) {
  funcall();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
