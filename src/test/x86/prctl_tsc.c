/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void skip_handler(__attribute__((unused)) int sig,
                         __attribute__((unused)) siginfo_t* si, void* user) {
  ucontext_t* ctx = (ucontext_t*)user;
#if defined(__i386__)
  ctx->uc_mcontext.gregs[REG_EIP] += 2;
#elif defined(__x86_64__)
  ctx->uc_mcontext.gregs[REG_RIP] += 2;
#else
#error unknown architecture
#endif
}

static void print_handler(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

static void exit_handler(__attribute__((unused)) int sig) { exit(77); }

int main(void) {
  int status;
  pid_t child;
  struct sigaction sa;

  test_assert(0 == prctl(PR_SET_TSC, PR_TSC_SIGSEGV));

  sa.sa_sigaction = skip_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGSEGV, &sa, NULL));

  child = fork();
  if (!child) {
    test_assert(0 == prctl(PR_GET_TSC, &status));
    test_assert(PR_TSC_SIGSEGV == status);
    signal(SIGSEGV, exit_handler);
    rdtsc();
    return 77;
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  signal(SIGSEGV, print_handler);
  test_assert(0 == prctl(PR_GET_TSC, &status));
  test_assert(PR_TSC_SIGSEGV == status);
  rdtsc();
  return 1;
}
