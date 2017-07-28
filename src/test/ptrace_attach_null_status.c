/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t child;
  struct timespec ts = { 0, 50000000 };

  if (0 == (child = fork())) {
    sleep(1000000);
    return 77;
  }

  nanosleep(&ts, NULL);
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, NULL, 0));

  test_assert(0 == kill(child, SIGKILL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
