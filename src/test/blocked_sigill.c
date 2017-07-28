/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void fault_handler(__attribute__((unused)) int sig,
                          __attribute__((unused)) siginfo_t* si,
                          __attribute__((unused)) void* context) {
  atomic_puts("FAILED: handler should not have been called for blocked signal");
}

static void* start_thread(__attribute__((unused)) void* p) {
  sigset_t s;

  sigemptyset(&s);
  sigaddset(&s, SIGILL);
  sigprocmask(SIG_BLOCK, &s, NULL);

  atomic_puts("EXIT-SUCCESS");

  asm("ud2");

  return NULL;
}

int main(void) {
  struct sigaction act;
  pthread_t thread;

  act.sa_sigaction = fault_handler;
  act.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&act.sa_mask);
  sigaction(SIGILL, &act, NULL);

  pthread_create(&thread, NULL, start_thread, NULL);
  pthread_join(thread, NULL);

  return 0;
}
