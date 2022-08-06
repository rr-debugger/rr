/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__i386__) || defined(__x86_64__)
char breakpoint_instruction[] = { 0xcc };
#elif defined(__aarch64__)
char breakpoint_instruction[] = { 0x0, 0x0, 0x20, 0xd4 };
#else
#error Unknown architecture
#endif

#define RR_PAGE_ADDR 0x70000000

int main(void) {
  uint8_t* syscall_addr = (uint8_t*)RR_PAGE_ADDR;
  uintptr_t current_brk = (uintptr_t)sbrk(0);
  // Write a breakpoint instruction to the vdso syscall address.
  // We don't do this by mprotecting, since we'd have to use RWX,
  // which may be disallowed by some kernels.
  int memfd = open("/proc/self/mem", O_RDWR);
  int nwritten = pwrite(memfd, &breakpoint_instruction,
                        sizeof(breakpoint_instruction), (uintptr_t)syscall_addr);
  if (nwritten == -1 && errno == EIO) {
    atomic_puts("Not running under rr");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(nwritten == sizeof(breakpoint_instruction));
  // Now make a syscall that we know rr will want to use a remote syscall
  // for. Don't use the glibc wrapper to make absolutely sure we don't hit
  // our own breakpoint.
  unbufferable_syscall(SYS_brk, current_brk + 0x100000, 0, 0);
  unbufferable_syscall(SYS_write, STDOUT_FILENO, (uintptr_t) "EXIT-SUCCESS", 14);
  // Exit directly.
  unbufferable_syscall(SYS_exit, 0x0, 0, 0);
  return 1;
}
