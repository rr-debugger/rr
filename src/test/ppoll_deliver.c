/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <poll.h>

static volatile int sighandler_called;

static void handle_signal(int sig) {
  test_assert(sig == SIGCHLD);
  sighandler_called = 1;
}

int main(void) {
  pid_t child;
  int ret;
  struct sigaction sa;
  sigset_t sigset;
  int status;
  struct timespec ten_ms = { 0, 10000000 };

  test_assert(0 == sigemptyset(&sigset));
  test_assert(0 == sigaddset(&sigset, SIGCHLD));
  test_assert(0 == sigprocmask(SIG_BLOCK, &sigset, NULL));

  child = fork();
  if (!child) {
    return 77;
  }
  /* Try to ensure the child has exited so the SIGCHLD is pending */
  test_assert(0 == nanosleep(&ten_ms, NULL));

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  test_assert(0 == sigaction(SIGCHLD, &sa, NULL));

  test_assert(0 == sigemptyset(&sigset));
  /* SIGCHLD should already be pending, so the syscallbuf ppoll will
     only do the untraced ppoll and defer the signal until we're
     exiting the syscallbuf. */
  ret = ppoll(NULL, 0, NULL, &sigset);
  test_assert(ret == -1 && errno == EINTR);

  test_assert(sighandler_called);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
