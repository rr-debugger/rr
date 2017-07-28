/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipefds[2];
static int pselect_pipe(int timeout, sigset_t* sigmask) {
  fd_set set;

  FD_ZERO(&set);
  FD_SET(pipefds[0], &set);
  struct timespec t;
  t.tv_sec = timeout;
  t.tv_nsec = 0;

  errno = 0;
  return pselect(pipefds[0] + 1, &set, NULL, NULL, timeout ? &t : NULL,
                 sigmask);
}

static int caught_signal;
static void handle_signal(__attribute__((unused)) int sig) { ++caught_signal; }

int main(void) {
  sigset_t sigmask;
  sigemptyset(&sigmask);

  pipe(pipefds);

  signal(SIGALRM, SIG_IGN);
  alarm(1);
  atomic_puts("ignoring SIGALRM, going into pselect ...");
  test_assert(0 == pselect_pipe(2, &sigmask) && 0 == errno);

  alarm(1);
  atomic_puts("ignoring SIGALRM (sigmask=NULL), going into pselect ...");
  test_assert(0 == pselect_pipe(2, NULL) && 0 == errno);

  /* Test that the signal mask is correct in rr when the SIGALRM is delivered */
  sigaddset(&sigmask, SIGCHLD);

  signal(SIGALRM, handle_signal);
  alarm(1);
  atomic_puts("handling SIGALRM, going into pselect ...");
  test_assert(-1 == pselect_pipe(0, &sigmask) && EINTR == errno);
  test_assert(1 == caught_signal);

  sigaddset(&sigmask, SIGALRM);
  alarm(1);
  atomic_puts("blocking SIGALRM, going into pselect ...");
  test_assert(0 == pselect_pipe(2, &sigmask) && 0 == errno);

  atomic_puts("EXIT-SUCCESS");
  return 1;
}
