/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void cpuid(int code, int subrequest, unsigned int* a, unsigned int* c,
                  unsigned int* d) {
  asm volatile("cpuid_instruction_label: cpuid"
               : "=a"(*a), "=c"(*c), "=d"(*d)
               : "a"(code), "c"(subrequest)
               : "ebx");
}

int main(void) {
  unsigned int a, c, d;
  /* CX ignored for AX==0 */
  cpuid(0, 2000, &a, &c, &d);
  test_assert(a > 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
