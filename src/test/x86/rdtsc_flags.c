/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
#ifdef __x86_64__
  char zero_ok;
  char nonzero_ok;
  uint64_t r11;

  /* Check that ZF=0 holds across buffered RDTSC
     and that R11 is preserved */
  asm volatile ("xor %%eax,%%eax\n\t"
                "xor %%r11,%%r11\n\t"
                "rdtsc\n\t"
                "mov %%rax,%%rcx\n\t" /* make it bufferable */
                "sete %0\n\t"
                "mov %%r11,%1\n\t"
                : "=m"(zero_ok), "=m"(r11) :: "eax", "edx", "rcx", "r11");
  test_assert(zero_ok);
  test_assert(r11 == 0);

  /* Check that ZF=1 holds across buffered RDTSC
     and that R11 is preserved */
  asm volatile ("xor %%eax,%%eax\n\t"
                "mov $1,%%r11d\n\t"
                "cmp $1,%%eax\n\t"
                "rdtsc\n\t"
                "mov %%rax,%%rcx\n\t" /* make it bufferable */
                "setne %0\n\t"
                "mov %%r11,%1\n\t"
                : "=m"(nonzero_ok), "=m"(r11) :: "eax", "edx", "rcx", "r11");
  test_assert(nonzero_ok);
  test_assert(r11 == 1);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

