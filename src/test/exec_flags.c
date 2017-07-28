/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void my_exec(const char* filename, const char** argv,
                    const char** envp) {
#ifdef __i386__
  /* Use a special instruction after the syscall to make sure we don't patch
     it */
  int out_bx;
  __asm__ __volatile__("xor %%ebx,%%ebx\n\t"
                       "xchg %%ebx,%%edi\n\t"
                       "int $0x80\n\t"
                       "xchg %%ebx,%%edi\n\t"
                       : "=b"(out_bx)
                       : "a"(SYS_execve), "c"(argv), "d"(envp), "D"(filename));
#elif defined(__x86_64__)
  int out_bx;
  /* Use a special instruction after the syscall to make sure we don't patch
     it */
  __asm__ __volatile__("xor %%ebx,%%ebx\n\t"
                       "syscall\n\t"
                       "xchg %%rdx,%%rdx\n\t"
                       : "=b"(out_bx)
                       : "a"(SYS_execve), "D"(filename), "S"(argv), "d"(envp));
#else
#error Unknown architecture
#endif
}

int main(__attribute__((unused)) int argc, const char* argv[],
         const char* envp[]) {
  my_exec("/no-exist!", argv, envp);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
