/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int value;
  asm volatile ("lsl %1,%0" : "=r"(value) : "r"(0x7b));
  atomic_printf("%d\n", value);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
