/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The kernel puts a frame record {x29, x30} of the interrupted code right
   above a signal handler's frame, in the 16 bytes below the interrupted sp
   (rounded down to a multiple of 16), and points the handler's x29 at it, so
   that unwinders can get from the handler to the interrupted code. Check that
   replay has it too. */

static volatile int handled;

static void handler(__attribute__((unused)) int sig,
                    __attribute__((unused)) siginfo_t* si, void* ctx) {
  ucontext_t* uc = ctx;
  uint64_t* record = (uint64_t*)((uc->uc_mcontext.sp - 16) & ~(uint64_t)15);
  test_assert(record[0] == uc->uc_mcontext.regs[29]);
  test_assert(record[1] == uc->uc_mcontext.regs[30]);
  handled = 1;
}

/* Send ourselves `sig` with a tgkill syscall. Just before, fill the 16 bytes
   where the kernel puts the frame record with a pattern, so that they can't
   hold the right values already. */
static void tgkill_self(int sig) {
  long pid = getpid();
  long tid = sys_gettid();
  register long x0 __asm__("x0") = pid;
  register long x1 __asm__("x1") = tid;
  register long x2 __asm__("x2") = sig;
  register long x8 __asm__("x8") = SYS_tgkill;
  __asm__ __volatile__("mov x9, sp\n\t"
                       "sub x9, x9, #16\n\t"
                       "and x9, x9, #-16\n\t"
                       "stp %[pattern], %[pattern], [x9]\n\t"
                       "svc #0\n\t"
                       : "+r"(x0)
                       : "r"(x1), "r"(x2), "r"(x8),
                         [pattern] "r"(0x5a5a5a5a5a5a5a5aUL)
                       : "x9", "memory");
  test_assert(x0 == 0);
}

int main(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  tgkill_self(SIGUSR1);
  test_assert(handled);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
