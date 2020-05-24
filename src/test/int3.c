/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  debug_trap();
  /* NB: the above instruction *must* be at line 6 in this file.
   * Tests rely on that. */
}

static void handle_sigtrap(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
  _exit(0);
}

int main(void) {
  signal(SIGTRAP, handle_sigtrap);

  atomic_puts("raising SIGTRAP ...");

  breakpoint();

  test_assert("didn't catch trap!" && 0);

  return 0;
}
