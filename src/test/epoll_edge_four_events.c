/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Return exactly 4 events (== EINTR) from a blocking edge-triggered epoll
   wait. syscallbuf used to mistake that result for an EINTR error and
   retry the wait as a traced syscall, which blocked forever because the
   edge-triggered events had already been consumed. */

#define NUM_FDS 4

static int pipe_fds[NUM_FDS][2];

static void make_readable(void) {
  int i;
  for (i = 0; i < NUM_FDS; ++i) {
    test_assert(1 == write(pipe_fds[i][1], "x", 1));
  }
}

int main(void) {
  struct epoll_event events[NUM_FDS + 1];
  int epfd;
  int i;
  int ret;

  epfd = epoll_create(1);
  test_assert(epfd >= 0);
  for (i = 0; i < NUM_FDS; ++i) {
    struct epoll_event ev = { EPOLLIN | EPOLLET, { 0 } };
    test_assert(0 == pipe(pipe_fds[i]));
    ev.data.fd = pipe_fds[i][0];
    test_assert(0 == epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[i][0], &ev));
  }

  make_readable();
  ret = epoll_wait(epfd, events, NUM_FDS + 1, -1);
  test_assert(ret == NUM_FDS);

  make_readable();
  ret = epoll_pwait(epfd, events, NUM_FDS + 1, -1, NULL);
  test_assert(ret == NUM_FDS);

  make_readable();
  ret = syscall(RR_epoll_pwait2, epfd, events, NUM_FDS + 1, NULL, NULL,
                (long)8);
  test_assert(ret == NUM_FDS || (ret == -1 && errno == ENOSYS));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
