/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  debug_trap();
  /* NB: the above instruction *must* be at line 6 in this file.
   * Tests rely on that. */
}

int main(void) {
  atomic_puts("doing int3 ...");

  breakpoint();

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
