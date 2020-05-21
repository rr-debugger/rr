/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) {
  sleep(1000);
  return NULL;
}

int main(void) {
  pthread_t thread;
  pid_t child;
  int status;

  pthread_create(&thread, NULL, do_thread, NULL);
  sched_yield();
  child = fork();
  if (child == 0) {
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }
  wait(&status);
  test_assert(WIFEXITED(status));
  test_assert(WEXITSTATUS(status) == 77);
  return 0;
}
