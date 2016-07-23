/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void* do_thread(__attribute__((unused)) void* p) {
  char* argv[] = { "/proc/self/exe", "dummy", NULL };
  atomic_puts("About to exec");
  execve("/proc/self/exe", argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

int main(int argc, __attribute__((unused)) char** argv) {
  pthread_t thread;

  if (argc > 1) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  pthread_create(&thread, NULL, do_thread, NULL);
  sleep(1000);
  test_assert(0 && "Failed something!");

  return 1;
}
