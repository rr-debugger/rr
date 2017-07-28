/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define RR_PAGE_ADDR 0x70000000

static uintptr_t my_syscall(uintptr_t syscall, uintptr_t arg1, uintptr_t arg2,
                            uintptr_t arg3) {
  uintptr_t ret;
#ifdef __x86_64__
  __asm__ volatile("syscall\n\t"
                   : "=a"(ret)
                   : "a"(syscall), "D"(arg1), "S"(arg2), "d"(arg3));
#elif defined(__i386__)
  __asm__ volatile("xchg %%esi,%%edi\n\t"
                   "int $0x80\n\t"
                   "xchg %%esi,%%edi\n\t"
                   : "=a"(ret)
                   : "a"(syscall), "b"(arg1), "c"(arg2), "d"(arg3));
#else
#error define syscall here
#endif
  return ret;
}

int main(void) {
  uint8_t* syscall_addr = (uint8_t*)RR_PAGE_ADDR;
  uintptr_t current_brk = (uintptr_t)sbrk(0);
  // Write a breakpoint instruction to the vdso syscall address.
  // We don't do this by mprotecting, since we'd have to use RWX,
  // which may be disallowed by some kernels.
  int memfd = open("/proc/self/mem", O_RDWR);
  uint8_t bp = 0xcc;
  int nwritten = pwrite(memfd, &bp, 1, (uintptr_t)syscall_addr);
  if (nwritten == -1 && errno == EIO) {
    atomic_puts("Not running under rr");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(nwritten == 1);
  // Now make a syscall that we know rr will want to use a remote syscall
  // for. Don't use the glibc wrapper to make absolutely sure we don't hit
  // our own breakpoint.
  my_syscall(SYS_brk, current_brk + 0x100000, 0, 0);
  my_syscall(SYS_write, STDOUT_FILENO, (uintptr_t) "EXIT-SUCCESS", 14);
  // Exit directly.
  my_syscall(SYS_exit, 0x0, 0, 0);
  return 1;
}
