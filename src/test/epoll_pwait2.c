/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handle_sig(__attribute__((unused)) int sig) {
  /* Don't do anything, just go through the signal handler motions */
}

int main(void) {
  int pipe_fd[2];
  int epfd = epoll_create(1 /*num events*/);
  struct timespec ts = { 5, 0 };
  struct epoll_event ev;
  sigset_t sigmask;
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGCHLD);

  signal(SIGALRM, handle_sig);

  test_assert(epfd >= 0);
  test_assert(0 == pipe(pipe_fd));

  ev.events = EPOLLIN;
  ev.data.fd = pipe_fd[0];
  test_assert(0 == epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev));

  // Make sure something will wake us from the epoll_pwait2.
  alarm(1);
  // But also use the epoll_pwait to modify the signal mask.
  syscall(RR_epoll_pwait2, epfd, &ev, 1, &ts, &sigmask, (long)8);
  test_assert(errno == EINTR || errno == ENOSYS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
