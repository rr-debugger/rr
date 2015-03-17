/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static volatile int v = 0;

static void breakpoint(void) {}

static void funcall(void) {
  char buf[2000000];
  int i;
  breakpoint();
  for (i = 0; i < sizeof(buf); ++i) {
    buf[i] = (char)i;
  }
  for (i = 0; i < sizeof(buf); ++i) {
    v += buf[i % 777777];
  }
}

int main(int argc, char* argv[]) {
  funcall();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
