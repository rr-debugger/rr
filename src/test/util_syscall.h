/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RRUTIL_SYSCALL_H
#define RRUTIL_SYSCALL_H

#include <stdint.h>

#if defined(__i386__)
#include "SyscallEnumsForTestsX86.generated"
#elif defined(__x86_64__)
#include "SyscallEnumsForTestsX64.generated"
#elif defined(__aarch64__)
#include "SyscallEnumsForTestsGeneric.generated"
#else
#error Unknown architecture
#endif

static inline uintptr_t unbufferable_syscall(uintptr_t syscall, uintptr_t arg1,
                                             uintptr_t arg2,
                                             uintptr_t arg3) {
  uintptr_t ret;
#ifdef __x86_64__
  __asm__ volatile("syscall\n\t"
                   /* Make sure we don't patch this syscall for syscall buffering */
                   "cmp $0x77,%%rax\n\t"
                   : "=a"(ret)
                   : "a"(syscall), "D"(arg1), "S"(arg2), "d"(arg3)
                   : "flags");
#elif defined(__i386__)
  __asm__ volatile("xchg %%esi,%%edi\n\t"
                   "int $0x80\n\t"
                   "xchg %%esi,%%edi\n\t"
                   : "=a"(ret)
                   : "a"(syscall), "b"(arg1), "c"(arg2), "d"(arg3));
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = syscall;
  register long x0 __asm__("x0") = (long)arg1;
  register long x1 __asm__("x1") = (long)arg2;
  register long x2 __asm__("x2") = (long)arg3;
  __asm__ volatile("b 1f\n\t"
                   "mov x8, 0xdc\n"
                   "1:\n\t"
                   "svc #0\n\t"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x8));
  ret = x0;
#else
#error define syscall here
#endif
  return ret;
}

#endif
