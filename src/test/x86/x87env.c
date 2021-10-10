/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifdef __x86_64__
extern char _x87_instruction;
static int cpu_has_xsave_fip_fdp_quirk(void) {
  uint64_t xsave_buf[576/sizeof(uint64_t)] __attribute__((aligned(64)));
  xsave_buf[1] = 0;
  asm volatile("finit\n"
               "fld1\n"
               "xsave64 %0\n"
               : "=m"(xsave_buf)
               : "a"(1), "d"(0)
               : "memory");
  return !xsave_buf[1];
}
#endif

int main(void) {
#ifdef __x86_64__
  long double x;
  uint32_t fstenv_buf[256];
  /* use mmap to get alignment >= 64 bytes */
  uint64_t* xsave_buf = (uint64_t*)mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  __asm__ volatile("finit\n"
                   "_x87_instruction: fld1\n");
  /* Trigger PLT code and syscall */
  sched_yield();
  __asm__ volatile("fstenv %1\n"
                   "xsave64 %2\n"
                   "fldz\n"
                   "fldenv %1\n"
                   : "=t"(x), "=m"(fstenv_buf), "=m"(*xsave_buf)
                   : "a"(0xffffffff), "d"(0xffffffff)
                   : "memory");
  test_assert(x == 1.0);
  /* Check saved FIPs */
  atomic_printf("FIP=0x%x\n", fstenv_buf[3]);
  if (cpu_has_xsave_fip_fdp_quirk()) {
    /* rr or the kernel should have cleared this during the sched_yield syscall */
    test_assert(fstenv_buf[3] == 0);
  } else {
    test_assert(fstenv_buf[3] == (uint32_t)(uintptr_t)&_x87_instruction);
  }
  atomic_printf("XSAVE FIP=0x%llx\n", (long long)xsave_buf[1]);
  if (cpu_has_xsave_fip_fdp_quirk()) {
    test_assert(xsave_buf[1] == 0);
  } else {
    test_assert(xsave_buf[1] == (uintptr_t)&_x87_instruction);
  }
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
