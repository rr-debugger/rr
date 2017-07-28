/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];
static pid_t child;

static void handle_sigterm(__attribute__((unused)) int sig,
                           __attribute__((unused)) siginfo_t* info,
                           __attribute__((unused)) void* mcontext) {
  char ch;
  /* Make sure our signals are enabled. This will hang if they
     aren't. */
  test_assert(1 == read(pipe_fds[0], &ch, 1));
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

int main(void) {
  struct sigaction sa;

  test_assert(0 == pipe(pipe_fds));

  child = fork();
  if (!child) {
    struct timespec ts = { 0, 1000000 };
    nanosleep(&ts, NULL);
    test_assert(1 == write(pipe_fds[1], "x", 1));
    return 77;
  }

  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = handle_sigterm;
  sigfillset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  kill(getpid(), SIGUSR1);

  return 0;
}
