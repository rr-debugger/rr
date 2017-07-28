/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int status = -1;

  if (syscall(SYS_clone, SIGCHLD, (intptr_t)-1, (intptr_t)-1, (intptr_t)-1,
              (intptr_t)-1) == 0) {
    _exit(0);
  }

  test_assert(wait(&status) >= 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
