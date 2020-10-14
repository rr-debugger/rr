/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

__attribute__((noinline))
static void cpuid(int code, int subrequest, unsigned int* a, unsigned int* c,
                  unsigned int* d) {
  asm volatile("cpuid_instruction_label: cpuid"
               : "=a"(*a), "=c"(*c), "=d"(*d)
               : "a"(code), "c"(subrequest)
               : "ebx");
}

int main(void) {
  unsigned int a, c, d;
  cpuid(0, 2000, &a, &c, &d);
  cpuid(0, 2000, &a, &c, &d);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
