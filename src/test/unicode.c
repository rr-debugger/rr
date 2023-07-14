/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char* breakpoint(char* arg) { return arg; }

int main(void) {
  breakpoint("\xf0\x9d\x95\xa8\xc4\x81\xe2\x89\xa5\x33");
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
