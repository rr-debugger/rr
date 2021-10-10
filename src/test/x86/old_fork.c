/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t child;
  int status;

  if (0 == (child = syscall(SYS_fork))) {
    return 11;
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 11);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
