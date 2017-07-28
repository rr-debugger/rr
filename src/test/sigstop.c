/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t child;
  int status = -1;
  struct timespec ts = { 0, 50000000 };

  if (0 == (child = fork())) {
    kill(getpid(), SIGSTOP);
    test_assert(0 && "child should not resume");
    return 77;
  }

  nanosleep(&ts, NULL);
  test_assert(0 == waitpid(child, &status, WNOHANG));
  test_assert(-1 == status);

  test_assert(0 == kill(child, SIGKILL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
