/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char ch = 'E';

static char my_write(int fd, void* buf, size_t size) {
/* Do a write syscall where the address of the buffer
   is at the top of stack during the syscall. This may trigger
   gdb to try to set a breakpoint in that buffer. */
#ifdef __x86_64__
  long ret;
  asm("push %5\n\t"
      "syscall\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      "pop %5\n\t"
      "mov (%5),%0\n\t"
      : "=a"(ret)
      : "a"(SYS_write), "D"(fd), "S"(buf), "d"(size), "r"(&ch));
#elif __i386__
  long ret;
  asm("push %5\n\t"
      "int $0x80\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      "pop %5\n\t"
      "mov (%5),%0\n\t"
      : "=a"(ret)
      : "a"(SYS_write), "b"(fd), "c"(buf), "d"(size), "r"(&ch));
#elif __aarch64__
  register long x0 __asm("x0") = fd;
  register long x1 __asm("x1") = (uintptr_t)buf;
  register long x2 __asm("x2") = size;
  register long x7 __asm("x7") = (uintptr_t)&ch;
  register long x8 __asm("x8") = SYS_write;
  asm("stp x1, x7, [sp, #-16]!\n\t"
      "svc #0\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      "ldp x1, x7, [sp], #16\n\t"
      "ldr x0, [x7]\n\t"
      : "+r"(x0)
      : "r"(x1), "r"(x2), "r"(x8), "r"(x7));
  long ret = x0;
#else
#error Unknown architecture
#endif
  return ret;
}

int main(void) {
  test_assert('E' == my_write(STDOUT_FILENO, &ch, 1));
  atomic_puts("XIT-SUCCESS");
  return 0;
}
