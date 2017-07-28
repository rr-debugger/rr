/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* thread(__attribute__((unused)) void* p) {
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &mask, NULL));

  test_assert(0 == kill(getpid(), SIGUSR1));
  test_assert(0 == kill(getpid(), SIGUSR2));

  return NULL;
}

static int usr1_hit;
static int usr2_hit;

static void handle_signal(int sig, __attribute__((unused)) siginfo_t* si,
                          __attribute__((unused)) void* ctx) {
  if (SIGUSR1 == sig) {
    ++usr1_hit;
  } else if (SIGUSR2 == sig) {
    ++usr2_hit;
  } else {
    test_assert("Unexpected signal" && 0);
  }
}

int main(void) {
  struct sigaction sa;
  pthread_t t;
  sigset_t mask;
  int ret;
  struct timespec ts;
  siginfo_t si;

  sa.sa_sigaction = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGUSR1, &sa, NULL);
  sigaction(SIGUSR2, &sa, NULL);

  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &mask, NULL));

  pthread_create(&t, NULL, thread, NULL);

  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  sigsuspend(&mask);

  test_assert(usr1_hit == 0);
  test_assert(usr2_hit == 1);

  test_assert(0 == sigpending(&mask));
  test_assert(1 == sigismember(&mask, SIGUSR1));
  test_assert(0 == sigismember(&mask, SIGUSR2));

  ts.tv_sec = 5;
  ts.tv_nsec = 0;
  ret = sigtimedwait(&mask, &si, &ts);
  atomic_printf("Signal %d became pending\n", ret);
  test_assert(SIGUSR1 == ret);
  test_assert(si.si_signo == SIGUSR1);
  test_assert(si.si_code == SI_USER);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
