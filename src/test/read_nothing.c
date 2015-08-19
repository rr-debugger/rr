/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  int pipe_fds[2];
  int i;
  char buf[1];

  test_assert(0 == pipe2(pipe_fds, O_NONBLOCK));
  for (i = 0; i < 10000; ++i) {
    test_assert(-1 == read(pipe_fds[0], buf, 100000000));
    test_assert(errno == EAGAIN);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
