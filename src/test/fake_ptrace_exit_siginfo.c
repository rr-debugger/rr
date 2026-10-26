/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* We send ourselves a SIGTRAP whose siginfo looks like that of a
   PTRACE_EVENT_EXIT stop. rr must deliver it like any other SIGTRAP. */

static volatile int handler_si_code;

static void handler(__attribute__((unused)) int sig, siginfo_t* si,
                    __attribute__((unused)) void* context) {
  handler_si_code = si->si_code;
}

int main(void) {
  struct sigaction sa;
  siginfo_t si;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGTRAP, &sa, NULL));

  memset(&si, 0, sizeof(si));
  si.si_signo = SIGTRAP;
  si.si_code = SIGTRAP | (PTRACE_EVENT_EXIT << 8);
  si.si_pid = getpid();
  test_assert(0 == syscall(SYS_rt_sigqueueinfo, getpid(), SIGTRAP, &si));
  test_assert(handler_si_code == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
