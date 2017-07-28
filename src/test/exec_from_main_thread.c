/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) {
  sleep(1000);
  test_assert(0 && "Failed something!");
  return NULL;
}

int main(int argc, __attribute__((unused)) char** argv) {
  pthread_t thread;
  char* args[] = { "/proc/self/exe", "dummy", NULL };

  if (argc > 1) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  pthread_create(&thread, NULL, do_thread, NULL);
  test_assert(0 == sched_yield());

  atomic_puts("About to exec");
  execve("/proc/self/exe", args, environ);
  test_assert(0 && "Failed exec!");

  return 1;
}
