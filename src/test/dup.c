/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char buf[] = "0123456789";

int main(void) {
  int pipe_fds[2];
  int fd;
  char ch;

  test_assert(0 == pipe(pipe_fds));
  test_assert(10 == write(pipe_fds[1], buf, 10));

  fd = dup(pipe_fds[0]);
  test_assert(fd >= 0);
  test_assert(fd != pipe_fds[0] && fd != pipe_fds[1]);
  test_assert(1 == read(fd, &ch, 1));
  test_assert(ch == '0');

  fd = dup2(pipe_fds[0], 0);
  test_assert(fd == 0);
  test_assert(1 == read(fd, &ch, 1));
  test_assert(ch == '1');

  fd = dup3(pipe_fds[0], 49, O_CLOEXEC);
  test_assert(fd == 49);
  test_assert(1 == read(fd, &ch, 1));
  test_assert(ch == '2');
  test_assert(FD_CLOEXEC == fcntl(fd, F_GETFD));

  test_assert(fd == dup2(0, fd));
  test_assert(0 == fcntl(fd, F_GETFD));

  fd = fcntl(pipe_fds[0], F_DUPFD, 49);
  test_assert(fd == 50);
  test_assert(1 == read(fd, &ch, 1));
  test_assert(ch == '3');
  test_assert(0 == fcntl(fd, F_GETFD));

  fd = fcntl(pipe_fds[0], F_DUPFD_CLOEXEC, 49);
  test_assert(fd == 51);
  test_assert(1 == read(fd, &ch, 1));
  test_assert(ch == '4');
  test_assert(FD_CLOEXEC == fcntl(fd, F_GETFD));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
