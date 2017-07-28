/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  atomic_puts("Line 1");
  atomic_puts("Line 2");
  atomic_puts("Line 3");
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
