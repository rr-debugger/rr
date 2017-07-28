/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, __attribute__((unused)) char** argv) {
  char* args[] = { "/proc/self/exe", "dummy", NULL };

  if (argc > 1) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  atomic_puts("ready");

  sleep(1);
  execve("/proc/self/exe", args, environ);
  test_assert(0 && "Failed exec!");
  return 1;
}
