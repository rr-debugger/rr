/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void do_rdtsc(void) {
#ifdef __RR_SOFTTICKS__
  /* Built for software ticks, the function's entry tick separates rdtsc from the
     `mov %rsp,%rbp` that rr's patching matches; the 5-byte nop is another pattern it
     patches (the tick's branch into it is allowed). */
  asm(".byte 0x0f, 0x1f, 0x44, 0x00, 0x00\n\t" /* nopl 0(%rax,%rax,1) */
      "rdtsc");
#else
  asm("rdtsc");
#endif
}

int main(void) {
  int i;
  for (i = 0; i < 2000000; ++i) {
    do_rdtsc();
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
