/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
static void breakpoint(void) {
  __asm__("int $3");
  /* NB: the above instruction *must* be at line 3 in this file.
   * Tests rely on that. */
}

#include "util.h"

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
