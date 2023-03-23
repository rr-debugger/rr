/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct timespec ts = { 10000, 0 };

static void handle_sigterm(__attribute__((unused)) int sig,
                           __attribute__((unused)) siginfo_t* info,
                           __attribute__((unused)) void* mcontext) {
  /* This simulates a process that takes a long time to exit on SIGTERM.
     Maybe it's a database trying to flush or a process that's trying to
     print backtraces or something. */
  nanosleep(&ts, NULL);
  exit(1);
}

int main(void) {
  struct sigaction sa;

  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = handle_sigterm;
  sigaction(SIGTERM, &sa, NULL);

  atomic_puts("sleeping");
  nanosleep(&ts, NULL);

  return 1;
}
