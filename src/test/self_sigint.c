/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  /* rr should ignore SIGINT */
  kill(getppid(), SIGINT);
  atomic_puts("EXIT-SUCCESS");
  kill(getpid(), SIGINT);
  test_assert(0 && "Shouldn't reach here");
  return 0;
}
