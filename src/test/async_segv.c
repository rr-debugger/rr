/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handle_segv(int sig) {
  test_assert(SIGSEGV == sig);
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

int main(void) {
  int dummy = 0, i;

  signal(SIGSEGV, handle_segv);

  atomic_puts("ready");

  /* No syscalls after here!  (Up to the assert.) */
  for (i = 1; i < (1 << 30); ++i) {
    dummy += (dummy + i) % 9735;
  }

  /* It's possible for SEGV to be delivered too late, so succeed anyway */
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
