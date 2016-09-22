/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#include <poll.h>

#define NUM_ITERATIONS 10

static void handle_sig(__attribute__((unused)) int sig) {
  sigset_t after_sigset;
  int ret = sigprocmask(SIG_BLOCK, NULL, &after_sigset);
  test_assert(ret == 0);
  test_assert(sigismember(&after_sigset, SIGCHLD));
}

int main(void) {
  int fds[2];
  struct pollfd pfd;
  int i;

  struct timespec t;
  t.tv_sec = 1;
  t.tv_nsec = 0;

  sigset_t sigset;
  test_assert(0 == sigemptyset(&sigset));
  test_assert(0 == sigaddset(&sigset, SIGCHLD));

  signal(SIGALRM, &handle_sig);

  pipe2(fds, O_NONBLOCK);

  pfd.fd = fds[0];
  pfd.events = POLLIN;
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    int ret;

    atomic_printf("iteration %d\n", i);
    if (i % 2 == 0) {
      ualarm(100000, 0);
    } else if (fork() == 0) {
      usleep(100000);
      return 0;
    }

    ret = ppoll(&pfd, 1, &t, &sigset);
    if (i % 2 == 0) {
      test_assert(ret == -1 && errno == EINTR);
    } else {
      test_assert(ret == 0);
    }

    sigset_t after_sigset;
    ret = sigprocmask(SIG_BLOCK, NULL, &after_sigset);
    test_assert(ret == 0);
    test_assert(!sigismember(&after_sigset, SIGCHLD));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
