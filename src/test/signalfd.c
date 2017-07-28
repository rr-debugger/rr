/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  sigset_t mask;
  int fd;
  struct signalfd_siginfo si;

  test_assert(0 == sigemptyset(&mask));
  test_assert(0 == sigaddset(&mask, SIGURG));
  fd = signalfd(-1, &mask, 0);
  test_assert(fd >= 0);

  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));

  test_assert(0 == kill(getpid(), SIGURG));
  test_assert(sizeof(si) == read(fd, &si, sizeof(si)));
  test_assert(si.ssi_signo == SIGURG);
  test_assert((pid_t)si.ssi_pid == getpid());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
