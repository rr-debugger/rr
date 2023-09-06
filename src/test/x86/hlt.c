/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void skip_handler(__attribute__((unused)) int sig,
                         __attribute__((unused)) siginfo_t* si, void* user) {
  ucontext_t* ctx = (ucontext_t*)user;
#if defined(__i386__)
  ctx->uc_mcontext.gregs[REG_EIP] += 1;
#elif defined(__x86_64__)
  ctx->uc_mcontext.gregs[REG_RIP] += 1;
#else
#error unknown architecture
#endif
}

int main(void) {
  int status;
  pid_t child;

  child = fork();
  if (!child) {
    struct sigaction sa;
    sa.sa_sigaction = skip_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    test_assert(0 == sigaction(SIGSEGV, &sa, NULL));

    asm volatile ("hlt");
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  return 0;
}
