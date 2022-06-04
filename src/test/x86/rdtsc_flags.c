/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
#ifdef __x86_64__
  char zero_ok;
  char nonzero_ok;

  /* Check that ZF=0 holds across buffered RDTSC */
  asm volatile ("xor %%eax,%%eax\n\t"
                "rdtsc\n\t"
                "mov %%rax,%%rcx\n\t" /* make it bufferable */
                "sete %0\n\t"
                : "=m"(zero_ok) :: "eax", "edx", "rcx");
  test_assert(zero_ok);

  /* Check that ZF=1 holds across buffered RDTSC */
  asm volatile ("xor %%eax,%%eax\n\t"
                "cmp $1,%%eax\n\t"
                "rdtsc\n\t"
                "mov %%rax,%%rcx\n\t" /* make it bufferable */
                "setne %0\n\t"
                : "=m"(nonzero_ok) :: "eax", "edx", "rcx");
  test_assert(nonzero_ok);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

