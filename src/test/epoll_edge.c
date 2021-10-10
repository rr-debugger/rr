/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;
  int pipe_fds[2];
  struct epoll_event event = { EPOLLIN | EPOLLET, { 0 } };

  fd = epoll_create(1);
  test_assert(fd >= 0);
  test_assert(0 == pipe(pipe_fds));
  test_assert(0 == epoll_ctl(fd, EPOLL_CTL_ADD, pipe_fds[0], &event));

  test_assert(1 == write(pipe_fds[1], "x", 1));
  test_assert(1 == epoll_wait(fd, &event, 1, 1000));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
