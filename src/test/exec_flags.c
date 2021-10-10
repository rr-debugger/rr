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
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = SYS_execve;
  register long x0 __asm__("x0") = (long)filename;
  register long x1 __asm__("x1") = (long)argv;
  register long x2 __asm__("x2") = (long)envp;
  // TODO: Prevent this from patching once we have syscallbuf support
  __asm__ __volatile__("svc #0"
                       : "+r"(x0)
                       : "r"(x8), "r"(x1), "r"(x2));
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
