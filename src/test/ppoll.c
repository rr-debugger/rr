/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

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

  uint64_t fake_sigset[10];
  fake_sigset[0] =
      (((uint64_t)1) << (SIGCHLD - 1)) | (((uint64_t)1) << (SIGPWR - 1));
  memset(&fake_sigset[1], 0xab, 9 * sizeof(uint64_t));

  signal(SIGALRM, &handle_sig);

  pipe2(fds, O_NONBLOCK);

  pfd.fd = fds[0];
  pfd.events = POLLIN;
  for (i = 0; i < NUM_ITERATIONS; i++) {
    int ret;

    atomic_printf("iteration %d\n", i);
    if (i % 2 == 0) {
      ualarm(100000, 0);
    } else if (fork() == 0) {
      usleep(100000);
      return 0;
    }

    sigset_t before_sigset;
    ret = sigprocmask(SIG_BLOCK, NULL, &before_sigset);
    test_assert(ret == 0);
    test_assert(!sigismember(&before_sigset, SIGALRM));

    t.tv_sec = 1;
    t.tv_nsec = 0;

    ret = syscall(SYS_ppoll, &pfd, 1, &t, &fake_sigset[0], sizeof(uint64_t));
    if (i % 2 == 0) {
      test_assert(ret == -1 && errno == EINTR);
    } else {
      test_assert(ret == 0);
    }

    /* Validate that we did not clobber fake_sigset memory */
    for (size_t i = 0; i < 9 * sizeof(uint64_t); ++i) {
      test_assert(((uint8_t*)(&fake_sigset[1]))[i] == 0xab);
    }

    /* Validate that the signal mask got reset */
    sigset_t after_sigset;
    ret = sigprocmask(SIG_BLOCK, NULL, &after_sigset);
    test_assert(ret == 0);
    test_assert(!sigismember(&after_sigset, SIGCHLD));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
