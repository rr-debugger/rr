/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void queue_siginfo(int sig, int val) {
  siginfo_t si;
  memset(&si, 0, sizeof(si));

  si.si_code = SI_QUEUE;
  si.si_pid = getpid();
  si.si_uid = geteuid();
  si.si_value.sival_int = val;
  syscall(SYS_rt_sigqueueinfo, getpid(), sig, &si);
}

static void queue_siginfo_tg(int sig, int val) {
  siginfo_t si;
  memset(&si, 0, sizeof(si));

  si.si_code = SI_QUEUE;
  si.si_pid = getpid();
  si.si_uid = geteuid();
  si.si_value.sival_int = val;
  syscall(SYS_rt_tgsigqueueinfo, getpid(), getpid(), sig, &si);
}

static int usr1_val;
static int usr2_val;

static void handle_signal(int sig, siginfo_t* si,
                          __attribute__((unused)) void* ctx) {
  int val = si->si_value.sival_int;
  if (SIGUSR1 == sig) {
    usr1_val = val;
  } else if (SIGUSR2 == sig) {
    usr2_val = val;
  } else {
    test_assert("Unexpected signal" && 0);
  }
}

int main(void) {
  struct sigaction sa;

  sa.sa_sigaction = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGUSR1, &sa, NULL);
  sigaction(SIGUSR2, &sa, NULL);

  queue_siginfo(SIGUSR1, -42);
  test_assert(-42 == usr1_val);
  queue_siginfo(SIGUSR2, 12345);
  test_assert(12345 == usr2_val);
  queue_siginfo_tg(SIGUSR1, -43);
  test_assert(-43 == usr1_val);
  queue_siginfo_tg(SIGUSR2, 123456);
  test_assert(123456 == usr2_val);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
