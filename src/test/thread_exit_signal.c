/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int count;
static volatile int stop;

static void handler(__attribute__((unused)) int sig) { ++count; }

static void handler2(__attribute__((unused)) int sig) { stop = 1; }

static void* do_thread(__attribute__((unused)) void* p) { return NULL; }

int main(void) {
  test_assert(0 == signal(SIGCHLD, handler));
  test_assert(0 == signal(SIGUSR2, handler2));

  atomic_puts("ready");

  while (!stop) {
    pthread_t thread;
    pthread_create(&thread, NULL, do_thread, NULL);
    pthread_join(thread, NULL);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
