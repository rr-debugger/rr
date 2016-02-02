/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int pipefds[2];
static int pselect_pipe(int timeout) {
  fd_set set;

  FD_ZERO(&set);
  FD_SET(pipefds[0], &set);
  struct timespec t;
  t.tv_sec = timeout;
  t.tv_nsec = 0;
  sigset_t sigmask;
  sigemptyset(&sigmask);

  errno = 0;
  return pselect(pipefds[0] + 1, &set, NULL, NULL, timeout ? &t : NULL,
                 &sigmask);
}

static int caught_signal;
static void handle_signal(__attribute__((unused)) int sig) { ++caught_signal; }

int main(void) {
  pipe(pipefds);

  signal(SIGALRM, SIG_IGN);
  alarm(1);
  atomic_puts("ignoring SIGALRM, going into pselect ...");
  test_assert(0 == pselect_pipe(2) && 0 == errno);

  signal(SIGALRM, handle_signal);
  alarm(1);
  atomic_puts("handling SIGALRM, going into pselect ...");
  test_assert(-1 == pselect_pipe(0) && EINTR == errno);
  test_assert(1 == caught_signal);

  atomic_puts("EXIT-SUCCESS");
  return 1;
}
