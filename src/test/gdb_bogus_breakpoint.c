/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char ch = 'E';

static char my_write(int fd, void* buf, size_t size) {
  long ret;
/* Do a write syscall where the address of the buffer
   is at the top of stack during the syscall. This may trigger
   gdb to try to set a breakpoint in that buffer. */
#ifdef __x86_64__
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
  asm("push %5\n\t"
      "int $0x80\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      "pop %5\n\t"
      "mov (%5),%0\n\t"
      : "=a"(ret)
      : "a"(SYS_write), "b"(fd), "c"(buf), "d"(size), "r"(&ch));
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
