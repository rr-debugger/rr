/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipefds[2];
static int poll_pipe(int timeout_ms) {
  struct pollfd pfd;
  int ret;

  pfd.fd = pipefds[0];
  pfd.events = POLLIN;
  errno = 0;
  ret = poll(&pfd, 1, timeout_ms);
  /* Verify that our input fields were not trashed */
  test_assert(pfd.fd == pipefds[0]);
  test_assert(pfd.events == POLLIN);
  return ret;
}

static int caught_signal;
static void handle_signal(__attribute__((unused)) int sig) { ++caught_signal; }

int main(void) {
  struct timespec dummy;

  test_assert(0 == pipe(pipefds));

  signal(SIGALRM, SIG_IGN);
  alarm(1);
  atomic_puts("ignoring SIGALRM, going into poll ...");
  test_assert(0 == poll_pipe(1500) && 0 == errno);

  signal(SIGALRM, handle_signal);
  alarm(1);
  atomic_puts("handling SIGALRM, going into poll ...");
  clock_gettime(CLOCK_MONOTONIC, &dummy);
  test_assert(-1 == poll_pipe(-1) && EINTR == errno);
  test_assert(1 == caught_signal);

  atomic_puts("EXIT-SUCCESS");
  return 1;
}
