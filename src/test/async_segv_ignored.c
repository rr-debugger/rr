/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  signal(SIGSEGV, SIG_IGN);

  kill(getpid(), SIGSEGV);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
