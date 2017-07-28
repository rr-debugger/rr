/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  signal(SIGSEGV, SIG_IGN);

  kill(getpid(), SIGSEGV);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
