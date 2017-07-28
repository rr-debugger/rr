/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
static void breakpoint(void) {
  __asm__("int $3");
  /* NB: the above instruction *must* be at line 3 in this file.
   * Tests rely on that. */
}

#include "util.h"

int main(void) {
  atomic_puts("doing int3 ...");

  breakpoint();

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
