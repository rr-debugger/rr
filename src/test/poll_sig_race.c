/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 10

int main(void) {
  int fds[2];
  struct pollfd pfd;
  int i;

  pipe2(fds, O_NONBLOCK);

  pfd.fd = fds[0];
  pfd.events = POLLIN;
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    char c;
    int ret;

    atomic_printf("iteration %d\n", i);

    if (0 == fork()) {
      usleep(250000);
      write(fds[1], "x", 1);
      return 0;
    }

    /* wait for 1 second, which should be long enough for
       the chlid to do its write. In extreme cases the
       child might run to completion before this poll()
       call is entered, in which case we will time out safely. */
    ret = poll(&pfd, 1, 1000);
    if (ret == 0) {
      continue;
    }
    test_assert(1 == ret);
    test_assert(POLLIN & pfd.revents);
    test_assert(1 == read(pfd.fd, &c, 1));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
