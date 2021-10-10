/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  uintptr_t val;
#if defined(__x86_64__) || defined(__i386__)
  asm ("breakpoint: pushf\n"
       "pop %0\n"
       : "=a"(val));
#else
#error Unknown architecture
#endif

  if (val & 0x100) {
    atomic_puts("TF set!");
    return 1;
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
