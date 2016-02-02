/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static int num_signals_caught;

static void handle_sigrt(int sig) {
  atomic_printf("Caught signal %d\n", sig);

  ++num_signals_caught;
}

static void my_raise(int sig) {
/* Don't call raise() directly, since that can go through our syscall hooks
   which mess up gdb's reverse-finish slightly. */
#ifdef __i386__
  int tid = getpid();
  /* Use a special instruction after the syscall to make sure we don't patch
     it */
  __asm__ __volatile__("xchg %%ebx,%%edi\n\t"
                       "int $0x80\n\t"
                       "xchg %%ebx,%%edi\n\t" ::"a"(SYS_tgkill),
                       "c"(tid), "d"(sig), "D"(tid));
#elif defined(__x86_64__)
  int tid = getpid();
  /* Use a special instruction after the syscall to make sure we don't patch
     it */
  __asm__ __volatile__("syscall\n\t"
                       "xchg %%rdx,%%rdx\n\t" ::"a"(SYS_tgkill),
                       "D"(tid), "S"(tid), "d"(sig));
#else
  raise(sig);
#endif
}

int main(void) {
  int i;

  for (i = SIGRTMIN; i <= SIGRTMAX; ++i) {
    breakpoint();
    signal(i, handle_sigrt);
    my_raise(i);
  }

  atomic_printf("caught %d signals; expected %d\n", num_signals_caught,
                1 + SIGRTMAX - SIGRTMIN);
  test_assert(1 + SIGRTMAX - SIGRTMIN == num_signals_caught);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
