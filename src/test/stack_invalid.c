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
#elif __aarch64__
  register long x8 __asm__("x8") = SYS_write;
  register long x0 __asm__("x0") = (long)fd;
  register long x1 __asm__("x1") = (long)buf;
  register long x2 __asm__("x2") = (long)size;
  register long x6 __asm__("x6") = 0;
  asm("mov x6, sp\n\t"
      "str x6,%1\n\t"
      "eor x6,x6,x6\n\t"
      "mov sp,x6\n\t"
      "svc #0\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      "ldr x6,%1\n\t"
      "mov sp,x6\n\t"
      : "+r"(x0), "+m"(saved_sp), "+r"(x6) :
      "r"(x1), "r"(x2), "r"(x8));
  ret = x0;
#else
#error Unknown architecture
#endif
  return ret;
}

int main(void) {
  test_assert(1 == my_write(STDOUT_FILENO, &ch, 1));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
