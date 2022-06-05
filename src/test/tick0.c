/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

// This is not linked to anything, not even the dynamic linker.

volatile int nloop = 100000;
const char exit_msg[] = "EXIT-SUCCESS\n";

#ifdef __x86_64__
#define SYS_write 1
#define SYS_exit 60
#define SYS_getpid 39
#elif defined(__i386__)
#define SYS_write 4
#define SYS_exit 1
#define SYS_getpid 20
#elif defined(__aarch64__)
#define SYS_write 64
#define SYS_exit 93
#define SYS_getpid 172
#else
#error define syscall numbers here
#endif


static inline __attribute__((always_inline))
unsigned long my_syscall(unsigned long syscall, unsigned long arg1,
                         unsigned long arg2, unsigned long arg3) {
  unsigned long ret;
#ifdef __x86_64__
  __asm__ volatile("syscall\n\t"
                   : "=a"(ret)
                   : "a"(syscall), "D"(arg1), "S"(arg2), "d"(arg3)
                   : "flags");
#elif defined(__i386__)
  __asm__ volatile("xchg %%esi,%%edi\n\t"
                   "int $0x80\n\t"
                   "xchg %%esi,%%edi\n\t"
                   : "=a"(ret)
                   : "a"(syscall), "b"(arg1), "c"(arg2), "d"(arg3));
#elif defined(__aarch64__)
  register unsigned long x8 __asm__("x8") = syscall;
  register unsigned long x0 __asm__("x0") = arg1;
  register unsigned long x1 __asm__("x1") = arg2;
  register unsigned long x2 __asm__("x2") = arg3;
  __asm__ volatile("svc #0\n\t"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x8));
  ret = x0;
#else
#error define syscall here
#endif
  return ret;
}

void _start(void) {
#ifdef HAS_TICK0
  my_syscall(SYS_getpid, 0, 0, 0);
#endif
  // Do some branches to make sure the very first event on this program
  // happens at ticks != 0
  for (int i = 0; i < nloop; i++) {
    asm volatile ("" : "+r"(i) :: "memory");
  }

  unsigned long nchar = sizeof(exit_msg) - 1; // remove terminal NUL byte

  my_syscall(SYS_write, 1, (unsigned long)exit_msg, nchar);
  my_syscall(SYS_exit, 0, 0, 0);
  __builtin_unreachable();
}
