/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void waittermsig(int sig, const char* waiter) {
  struct timespec ts = {.tv_sec = 1 };
  sigset_t set;
  siginfo_t si;

  sigemptyset(&set);
  sigaddset(&set, sig);
  sigtimedwait(&set, &si, &ts);

  atomic_printf("FAILED: %s: signal %d either not caught or didn't terminate "
                "process within 1 second\n",
                waiter, sig);
}

static void* kill_thread(__attribute__((unused)) void* dontcare) {
  const int termsig = SIGTERM;

  atomic_puts("killing...");
  kill(getpid(), termsig);
  waittermsig(termsig, "kill_thread");
  return NULL; /* not reached */
}

int main(void) {
  pthread_t t;

  pthread_create(&t, NULL, kill_thread, NULL);
  pthread_join(t, NULL);
  atomic_puts("FAILED: joined thread that should have died");
  return 0;
}
