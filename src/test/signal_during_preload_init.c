/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {
  atomic_puts("In handler");
}

static void* run_child(__attribute__((unused)) void* arg) {
  sched_yield();
  return 0;
}

int main(void) {
  pthread_t thread;

  signal(SIGCHLD, handler);

  pthread_create(&thread, NULL, run_child, NULL);
  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
