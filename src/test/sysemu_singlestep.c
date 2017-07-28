/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int var = 41;

#ifdef __i386__
  __asm__ __volatile__("int $0x80\n\t"
                       "incl %0\n\t"
                       : "=m"(var)
                       : "a"(SYS_gettid));
#elif defined(__x86_64__)
  __asm__ __volatile__("syscall\n\t"
                       "incl %0\n\t"
                       : "=m"(var)
                       : "a"(SYS_gettid));
#endif

  test_assert(var == 42);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
