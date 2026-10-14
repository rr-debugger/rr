/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A signal handler can make sigreturn put a -ERESTART* value in the syscall
   result register. sigreturn makes the kernel forget that the task is in a
   syscall, so nothing gets restarted: the task continues at the pc the
   handler set, with that value. */

#define ERESTARTSYS 512

void landing_stub(void);
void landing(long result);
void restarted(void);

#if defined(__x86_64__)
#define RESULT_REG gregs[REG_RAX]
#define PC_REG gregs[REG_RIP]
/* Pass %rax to landing() with the stack aligned as at a function entry. */
__asm__(".text\n"
        ".globl landing_stub\n"
        "landing_stub:\n\t"
        "mov %rax, %rdi\n\t"
        "and $-16, %rsp\n\t"
        "sub $8, %rsp\n\t"
        "jmp landing\n\t");
#elif defined(__i386__)
#define RESULT_REG gregs[REG_EAX]
#define PC_REG gregs[REG_EIP]
__asm__(".text\n"
        ".globl landing_stub\n"
        "landing_stub:\n\t"
        "and $-16, %esp\n\t"
        "sub $12, %esp\n\t"
        "push %eax\n\t"
        "call landing\n\t");
#elif defined(__aarch64__)
#define RESULT_REG regs[0]
#define PC_REG pc
/* x0 is landing()'s argument already. If the task went back one instruction
   to restart a syscall, it would branch to restarted() instead. */
__asm__(".text\n"
        ".p2align 2\n\t"
        "b restarted\n"
        ".globl landing_stub\n"
        "landing_stub:\n\t"
        "b landing\n\t");
#else
#error Unknown architecture
#endif

static void handle_sigill(__attribute__((unused)) int sig,
                          __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = (ucontext_t*)p;
  ctx->uc_mcontext.RESULT_REG = (uintptr_t)-ERESTARTSYS;
  ctx->uc_mcontext.PC_REG = (uintptr_t)landing_stub;
}

void restarted(void) {
  test_assert(0 && "sigreturn restarted a syscall");
}

void landing(long result) {
  test_assert(result == -ERESTARTSYS);
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

int main(void) {
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_sigill;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGILL, &sa, NULL));

#if defined(__aarch64__)
  __asm__ __volatile__("udf #0");
#else
  __asm__ __volatile__("ud2");
#endif
  test_assert(0 && "Didn't land");
  return 0;
}
