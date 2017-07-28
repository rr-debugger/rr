/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int dummy = 0, i;

  /* NB: since we're masking out the signal, there's no way for
   * us to tell whether or not it was actually delivered.  This
   * test can spuriously pass if it's never sent SIGUSR1. */

  signal(SIGUSR1, SIG_IGN);

  atomic_puts("SIGUSR1 disabled");

  for (i = 1; i < (1 << 27); ++i) {
    dummy += (dummy + i) % 9735;
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
