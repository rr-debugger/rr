/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t c;
  int dummy = 0, i;
  int status;

  atomic_puts("forking child");

  if (0 == (c = fork())) {
    usleep(10000);
    atomic_puts("child exiting");
    exit(0);
  }

  /* NO SYSCALLS AFTER HERE!  (Up to the test_asserts.) */
  for (i = 1; i < (1 << 28); ++i) {
    dummy += (dummy + i) % 9735;
  }

  test_assert(c == waitpid(c, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
