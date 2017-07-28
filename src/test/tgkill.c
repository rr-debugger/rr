/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int num_signals_caught;

static int tgkill(int tgid, int tid, int sig) {
  return syscall(SYS_tgkill, tgid, tid, sig);
}

static void sighandler(int sig) {
  atomic_printf("Task %d got signal %d\n", sys_gettid(), sig);
  ++num_signals_caught;
}

int main(void) {
  signal(SIGUSR1, sighandler);
  signal(SIGUSR2, sighandler);
  tgkill(getpid(), sys_gettid(), SIGUSR1);
  tgkill(getpid(), sys_gettid(), SIGUSR2);

  test_assert(2 == num_signals_caught);

  syscall(SYS_tkill, sys_gettid(), SIGUSR1);
  syscall(SYS_tkill, sys_gettid(), SIGUSR2);

  test_assert(4 == num_signals_caught);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
