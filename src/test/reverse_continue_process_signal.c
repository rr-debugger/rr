/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS (1 << 26)

int spin(void) {
  int i, dummy = 0;

  atomic_puts("spinning");
  for (i = 1; i < NUM_ITERATIONS; ++i) {
    dummy += i % (1 << 20);
    dummy += i % (79 * (1 << 20));
  }
  return dummy;
}

int main(void) {
  pid_t pid;
  int status;

  pid = fork();
  if (0 == pid) {
    signal(SIGINT, SIG_IGN);
    spin();
    kill(getpid(), SIGINT);
    return 77;
  }

  test_assert(pid == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
