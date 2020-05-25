/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/**
 * This test makes sure that replay does not fail if the instruction after a
 * system call is non-idempotent. For each architecture, the assembly sequence
 * should issue a system call, followed immediately by an increment operation
 * or other non-idempotent operation on a memory address.
 */

int main(void) {
  int var = 41;

#ifdef __i386__
  __asm__ __volatile__("int $0x80\n\t"
                       "incl %0\n\t"
                       : "+m"(var)
                       : "a"(SYS_gettid));
#elif defined(__x86_64__)
  __asm__ __volatile__("syscall\n\t"
                       "incl %0\n\t"
                       : "+m"(var)
                       : "a"(SYS_gettid));
#elif defined(__aarch64__)
  // We use an atomic instruction here, because we need to do a read-modify
  // write cycle all in one instruction. Everything else would be idempotent
  register long x8 __asm__("x8") = SYS_gettid;
  register long x1 __asm__("x1") = 1;
  register long x0 __asm__("x0") = 0;
  __asm__ __volatile__("svc #0\n\t"
                       "stadd w1, %0\n\t"
                       : "+Q"(var), "+r"(x0)
                       : "r"(x8), "r"(x1));
#else
#error Define your architecture here
#endif

  test_assert(var == 42);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
