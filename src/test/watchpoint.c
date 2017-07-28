/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static int var;

static void* thread(__attribute__((unused)) void* unused) {
  var = 1337;
  return NULL;
}

int main(void) {
  pthread_t t;

  breakpoint();

  var = 42;

  pthread_create(&t, NULL, thread, NULL);
  pthread_join(t, NULL);

  atomic_printf("var=%d\n", var);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
