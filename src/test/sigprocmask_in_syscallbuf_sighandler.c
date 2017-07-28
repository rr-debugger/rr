/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];

static void handle_signal(__attribute__((unused)) int sig) {
  sigset_t mask;

  atomic_puts("Caught SIGALRM");

  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  test_assert(0 == sigprocmask(SIG_BLOCK, &mask, NULL));

  /* Syscallbuf should be still locked here. If it's not this
     could corrupt syscallbuf state. */
  test_assert(2 == write(pipe_fds[1], "xx", 2));
}

int main(void) {
  struct sigaction sact;
  char buf;

  test_assert(0 == pipe(pipe_fds));

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_RESTART;
  sact.sa_handler = handle_signal;
  test_assert(0 == sigaction(SIGALRM, &sact, NULL));

  test_assert(0 == alarm(1));
  /* If the syscallbuf state is corrupted by the signal handler
     we'll probably crash out here. */
  test_assert(1 == read(pipe_fds[0], &buf, 1));
  /* Or here */
  test_assert(1 == read(pipe_fds[0], &buf, 1));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
