#include "util.h"

#include <sys/auxv.h>
#include <sys/prctl.h>
#include <stdio.h>

// For compatibility with pre-2.38 versions of binutils.
#define cntvctss_el0 "s3_3_c14_c0_6"

long cntfrq(void) {
  long c;
  __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(c));
  return c;
}

long cntvct(void) {
  long c;
  __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(c));
  return c;
}

long cntvctss(void) {
  long c;
  if (getauxval(AT_HWCAP2) & HWCAP2_ECV) {
    __asm__ __volatile__(".arch armv8.6-a\nmrs %0, " cntvctss_el0 : "=r"(c));
  } else {
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(c));
  }
  return c;
}

long initial_cntfrq;
long initial_cntvct;

void arch_timer_nops(void) {
  __asm__ __volatile__("mrs xzr, cntfrq_el0");
  __asm__ __volatile__("mrs xzr, cntvct_el0");
  if (getauxval(AT_HWCAP2) & HWCAP2_ECV) {
    __asm__ __volatile__("mrs xzr, " cntvctss_el0);
  }
}

void diversion_check(void) {
  arch_timer_nops();
  test_assert(initial_cntfrq == cntfrq());
  test_assert(initial_cntvct < cntvct());
  test_assert(initial_cntvct < cntvctss());
  atomic_puts("diversion_check passed");
}

void breakpoint(void) {}

int main(void) {
  initial_cntfrq = cntfrq();
  initial_cntvct = cntvct();
  breakpoint();

  atomic_printf("%ld\n", cntvct());
  atomic_printf("%ld\n", cntvctss());
  atomic_printf("%ld\n", cntfrq());

  arch_timer_nops();

  atomic_puts("EXIT-SUCCESS");
}
