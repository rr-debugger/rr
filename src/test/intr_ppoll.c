/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#include <poll.h>

#define NUM_ITERATIONS 10

static void handle_sig(__attribute__((unused)) int sig) {
  sigset_t after_sigset;
  int ret = sigprocmask(SIG_BLOCK, NULL, &after_sigset);
  test_assert(ret == 0);
  test_assert(sigismember(&after_sigset, SIGCHLD));

  // Waste time.
  int j = 0;
  for (int i = 0; i < 1000000000; i++) {
    j = i + j % 2347;
  }
}

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

  signal(SIGALRM, &handle_sig);

  pid_t pid = getpid();

  pipe2(fds, O_NONBLOCK);

  pfd.fd = fds[0];
  pfd.events = POLLIN;
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    int ret;

    atomic_printf("iteration %d\n", i);
    if (fork() == 0) {
      usleep(100000);
      kill(pid, SIGWINCH);
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
