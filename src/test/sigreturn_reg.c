/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

volatile int caught_sig = 0;
long long v = 99;

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
#ifdef __x86_64__
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  test_assert(ctx->uc_mcontext.gregs[REG_RCX] == 0);
  test_assert(ctx->uc_mcontext.gregs[REG_RDI] == 0);
  ctx->uc_mcontext.gregs[REG_RDI] = (long long)&v;
#elif defined(__aarch64__)
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  test_assert(ctx->uc_mcontext.regs[1] == 0);
  test_assert(ctx->uc_mcontext.regs[2] == 0);
  ctx->uc_mcontext.regs[2] = (long)&v;
#endif
  caught_sig = signum;
}

int main(void) {
  struct sigaction sact;
  long long ax = v;
  long long cx = 0;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGSEGV, &sact, NULL);

#ifdef __x86_64__
  ax = 0;
  __asm__("\txor %%rdi,%%rdi\n"
          "\txor %%rcx,%%rcx\n"
          "\tmov (%%rdi),%%rax\n"
          : "=c"(cx), "=a"(ax)
          :: "memory");
  test_assert(caught_sig == SIGSEGV);
#elif defined(__aarch64__)
  ax = 0;
  register long x0 __asm__("x0") = ax;
  register long x1 __asm__("x1") = cx;
  register long x2 __asm__("x2") = (long)0;
  __asm__("\tmov x2, xzr\n"
          "\tmov x1, xzr\n"
          "\tldr x0, [x2]\n"
          : "+r"(x0), "+r"(x1), "+r"(x2)
          :: "memory");
  ax = x0;
  cx = x1;
  test_assert(caught_sig == SIGSEGV);
#endif

  test_assert(cx == 0);
  test_assert(ax == v);
  atomic_puts("EXIT-SUCCESS");

  return 0;
}
