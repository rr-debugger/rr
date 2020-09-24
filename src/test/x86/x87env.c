/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

extern char _x87_instruction;

int main(void) {
#ifdef __x86_64__
  long double x;
  uint32_t buf[256];
  __asm__ volatile("_x87_instruction: fld1\n");
  /* Trigger PLT code and syscall */
  sched_yield();
  __asm__ volatile("fstenv %1\n"
                   "fldz\n"
                   "fldenv %1\n"
                   : "=t"(x), "=m"(buf)
                   :
                   : "memory");
  test_assert(x == 1.0);
  /* Check saved FIP */
  atomic_printf("FIP=0x%x\n", buf[3]);
  test_assert(buf[3] == (uint32_t)(long)&_x87_instruction);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
