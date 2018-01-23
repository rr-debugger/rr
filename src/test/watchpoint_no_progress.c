/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifdef __x86_64__
__asm__ ("my_syscall: mov %rdi,%rax\n\t"
         "syscall_instruction: syscall\n\t"
         "ret");
#elif defined(__i386__)
__asm__ ("my_syscall: mov 4(%esp),%eax\n\t"
         "syscall_instruction: int $0x80\n\t"
         "ret");
#else
#error define syscall here
#endif

extern void my_syscall(int number);

int main(void) {
  my_syscall(SYS_sched_yield);
  atomic_puts("EXIT-SUCCESS");
  return 1;
}
