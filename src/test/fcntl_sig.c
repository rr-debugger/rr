/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  test_assert(0 == fcntl(1, F_SETSIG, SIGCHLD));
  test_assert(SIGCHLD == fcntl(1, F_GETSIG, 0));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
