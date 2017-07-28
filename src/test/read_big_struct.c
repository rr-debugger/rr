/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

/* FIXME: we should be able to send arbitrarily large structs over the
 * debugging socket.  This is a temporary hack. */
struct big {
  char bytes[8192];
};

int main(void) {
  struct big big;

  memset(&big, 0x5a, sizeof(big));

  breakpoint();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
