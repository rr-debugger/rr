/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <poll.h>

#define NUM_ITERATIONS 10

int main(void) {
  int fds[2];
  struct pollfd pfd;
  int i;

  struct timespec t;
  t.tv_sec = 2;
  t.tv_nsec = 0;

  sigset_t sigset;
  test_assert(0 == sigemptyset(&sigset));
  test_assert(0 == sigaddset(&sigset, SIGCHLD));

  signal(SIGALRM, SIG_IGN);

  pid_t pid = getpid();

  pipe2(fds, O_NONBLOCK);

  pfd.fd = fds[0];
  pfd.events = POLLIN;
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    int ret;

    atomic_printf("iteration %d\n", i);
    if (fork() == 0) {
      usleep(100000);
      // SIGCHLD will be unblocked once these signals are delivered.
      // Half the time we send SIGALRM too, to verify that SIGCHLD only becomes
      // unblocked after *all* of these are delivered.
      kill(pid, SIGWINCH);
      if (i % 2) {
        kill(pid, SIGALRM);
      }
      return 0;
    }

    ret = ppoll(&pfd, 1, &t, &sigset);

    sigset_t after_sigset;
    ret = sigprocmask(SIG_BLOCK, NULL, &after_sigset);
    test_assert(ret == 0);
    test_assert(!sigismember(&after_sigset, SIGCHLD));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
