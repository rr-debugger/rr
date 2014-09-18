/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void fault_handler(int sig, siginfo_t* si, void* context) {
  atomic_puts("FAILED: handler should not have been called for blocked signal");
}

static void* start_thread(void* p) {
  sigset_t s;

  sigemptyset(&s);
  sigaddset(&s, SIGSEGV);
  sigprocmask(SIG_BLOCK, &s, NULL);

  atomic_puts("EXIT-SUCCESS");

  *(int*)NULL = 0;

  return NULL;
}

int main(int argc, char* argv[]) {
  struct sigaction act;
  pthread_t thread;

  act.sa_sigaction = fault_handler;
  act.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&act.sa_mask);
  sigaction(SIGSEGV, &act, NULL);

  pthread_create(&thread, NULL, start_thread, NULL);
  pthread_join(thread, NULL);

  return 0;
}
