/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <signal.h>

static char buf[128 * 1024];

static void handler(int sig,
                    __attribute__((unused)) siginfo_t* si,
                    __attribute__((unused)) void* ucontext_ptr) {
  test_assert(sig == SIGSEGV);

#ifdef __x86_64__
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  // Skip the current instruction.
  ctx->uc_mcontext.gregs[REG_RIP] += 2;
#elif defined(__i386__)
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  // Skip the current instruction.
  ctx->uc_mcontext.gregs[REG_EIP] += 2;
#else
  test_assert(0);
#endif
}

int main(void) {
  stack_t* ss;

  ALLOCATE_GUARD(ss, 'x');
  ss->ss_sp = buf;
  ss->ss_flags = 0;
  ss->ss_size = sizeof(buf);
  test_assert(0 == sigaltstack(ss, NULL));
  VERIFY_GUARD(ss);

  struct sigaction sig;
  sig.sa_sigaction = handler;
  sigemptyset(&sig.sa_mask);
  sig.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
  test_assert(0 == sigaction(SIGILL, &sig, NULL));
  sig.sa_flags |= SA_ONSTACK;
  test_assert(0 == sigaction(SIGSEGV, &sig, NULL));

#ifdef __x86_64__
  asm volatile("mov %%rsp, %%rax\n"
               "mov $0x800794b90ed0, %%rsp\n"
               "ud2\n"
               "mov %%rax, %%rsp\n"
	       : : : "rax");
#elif defined(__i386__)
  asm volatile("mov %%esp, %%eax\n"
               "mov $0xdeafbeef, %%esp\n"
               "ud2\n"
               "mov %%eax, %%esp\n"
	       : : : "eax");
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
