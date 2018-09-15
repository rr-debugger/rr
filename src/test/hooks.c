/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int do_close(int fd);

const int sys_close = SYS_close;

#ifdef __x86_64__
asm (".text\n"
     "do_close:\n\t"
     "mov sys_close(%rip),%eax\n\t"
     "syscall\n\t"
     "ret\n\t"
     ".byte 0x0f, 0x1f, 0x44, 0, 0");
#else
int do_close(int fd) {
  return close(fd);
}
#endif

int main(void) {
  int i;
  for (i = 0; i < 1000000; ++i) {
    do_close(50000);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

