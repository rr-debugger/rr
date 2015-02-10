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
#ifdef __i386__
  /* Don't call raise() directly, since that can go through our syscall hooks
     which mess up gdb's reverse-finish slightly. */
  int tid = getpid();
  __asm__ __volatile__("int $0x80\n\t"
                       :: "a"(SYS_tgkill), "b"(tid), "c"(tid), "d"(sig));
#else
  raise(sig);
#endif
}

int main(int argc, char* argv[]) {
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
