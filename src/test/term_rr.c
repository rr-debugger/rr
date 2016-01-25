/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  atomic_puts("EXIT-SUCCESS");
  kill(getppid(), SIGTERM);
  return 0;
}
