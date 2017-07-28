/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_PFDS 200

int main(void) {
  int fds[2];
  struct pollfd pfds[NUM_PFDS];
  char ch = 'x';
  int i;

  pipe(fds);

  for (i = 0; i < NUM_PFDS; ++i) {
    pfds[i].fd = fds[0];
    pfds[i].events = POLLIN;
  }

  if (fork() == 0) {
    usleep(1000);
    write(fds[1], &ch, 1);
    return 0;
  }

  /* This should block */
  test_assert(NUM_PFDS == poll(pfds, NUM_PFDS, -1));
  test_assert(POLLIN & pfds[0].revents);
  test_assert(1 == read(pfds[0].fd, &ch, 1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
