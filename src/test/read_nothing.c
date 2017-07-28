/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SIZE 100000000

int main(void) {
  int pipe_fds[2];
  int i;
  char* buf = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  test_assert(buf != MAP_FAILED);
  test_assert(0 == pipe2(pipe_fds, O_NONBLOCK));
  for (i = 0; i < 10000; ++i) {
    test_assert(-1 == read(pipe_fds[0], buf, SIZE));
    test_assert(errno == EAGAIN);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
