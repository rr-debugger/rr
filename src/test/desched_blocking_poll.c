/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  int fds[2];
  struct pollfd pfd;
  char ch = 'x';

  pipe(fds);

  pfd.fd = fds[0];
  pfd.events = POLLIN;
  if (fork() == 0) {
    usleep(1000);
    write(fds[1], &ch, 1);
    return 0;
  }

  /* This should block */
  test_assert(1 == poll(&pfd, 1, -1));
  test_assert(POLLIN & pfd.revents);
  test_assert(1 == read(pfd.fd, &ch, 1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
