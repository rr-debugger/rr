/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char ch = 'E';
static long saved_sp;

static ssize_t my_write(int fd, void* buf, size_t size) {
  ssize_t ret;
/* Do a write syscall with no valid stack. */
#ifdef __x86_64__
  asm("mov %%rsp,%5\n\t"
      "xor %%rsp,%%rsp\n\t"
      "syscall\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      "mov %5,%%rsp\n\t"
      : "=a"(ret)
      : "a"(SYS_write), "D"(fd), "S"(buf), "d"(size), "m"(saved_sp));
#elif __i386__
  asm("mov %%esp,%5\n\t"
      "xor %%esp,%%esp\n\t"
      "int $0x80\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      "mov %5,%%esp\n\t"
      : "=a"(ret)
      : "a"(SYS_write), "b"(fd), "c"(buf), "d"(size), "m"(saved_sp));
#else
#error Unknown architecture
#endif
  return ret;
}

int main(void) {
  test_assert(1 == my_write(STDOUT_FILENO, &ch, 1));
  atomic_puts("XIT-SUCCESS");
  return 0;
}
