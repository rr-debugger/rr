/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int depth = 0;
static char buf[SIGSTKSZ];

static void SEGV_handler(int sig, siginfo_t* si, void* context) {
  atomic_printf("depth = %d\n", depth);
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

static int recurse(void) {
  ++depth;
  return recurse() * 13 + 1;
}

int main(int argc, char* argv[]) {
  /* Testing shows that the output value of |depth| is not very sensitive to
     small values of the limit, but it's very sensitive around the 500K mark.
  */
  struct rlimit r = { 500000, 500000 };
  struct sigaction act;
  stack_t stack;

  stack.ss_flags = 0;
  stack.ss_size = sizeof(buf);
  stack.ss_sp = buf;
  test_assert(0 == sigaltstack(&stack, NULL));

  act.sa_sigaction = SEGV_handler;
  act.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&act.sa_mask);
  test_assert(0 == sigaction(SIGSEGV, &act, NULL));

  test_assert(0 == setrlimit(RLIMIT_STACK, &r));

  return recurse();
}
