/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int result = 0;

static void funcallD(int n) { result = n; }

static void funcallC(int n) {
  funcallD(n);
  funcallD(n);
}

static void funcallB(int n) {
  funcallC(n);
  funcallC(n);
}

static void funcallA(int n) {
  funcallB(n);
  funcallB(n);
}

static void funcall(int n) {
  funcallA(n);
  funcallA(n);
}

int main(void) {
  funcall(1);
  funcall(1);

  atomic_printf("result=%d\n", result);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
