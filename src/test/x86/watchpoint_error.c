/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char buffer[64];

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  strcpy(buffer, "hello");
  return 0;
}
