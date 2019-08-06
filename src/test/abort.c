/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  kill(0, SIGABRT);
  return 0;
}
