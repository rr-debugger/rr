/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int8_t control = SYSCALL_DISPATCH_FILTER_BLOCK;

static void handler(int sig, siginfo_t* si, void*) {
  control = SYSCALL_DISPATCH_FILTER_ALLOW;
  test_assert(sig == SIGSYS);
  test_assert(si->si_code == SYS_USER_DISPATCH);
  atomic_puts("Not running under rr apparently");
}

int main(void) {
  struct sigaction sa;

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  int ret = prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, 0, 0, &control);
  if (ret == -1 && errno == EINVAL) {
    atomic_puts("PR_SET_SYSCALL_USER_DISPATCH not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret >= 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
