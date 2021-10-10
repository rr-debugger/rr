/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handle_sig(__attribute__((unused)) int sig) {
  /* Don't do anything, just go through the signal handler motions */
}

int main(void) {
  int pipe_fd[2];
  int epfd;
  struct epoll_event ev;
  sigset_t sigmask;
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGCHLD);

  signal(SIGALRM, handle_sig);

  test_assert(0 == pipe(pipe_fd));
  test_assert(0 <= (epfd = epoll_create(1 /*num events*/)));

  ev.events = EPOLLIN;
  ev.data.fd = pipe_fd[0];
  test_assert(0 == epoll_ctl(epfd, EPOLL_CTL_ADD, ev.data.fd, &ev));

  // Make sure something will wake us from the epoll_pwait.
  alarm(1);
  // But also use the epoll_pwait to modify the signal mask.
  epoll_pwait(epfd, &ev, 1, 5000, &sigmask);
  test_assert(errno == EINTR);
  // We didn't die, yay!.
  // The sigreturn will clean up the kernel's internal state.

  // Now do it again, but don't rely on sigreturn to clean up
  // the kernel state.
  signal(SIGALRM, SIG_IGN);

  // Make sure something will wake us from the epoll_pwait.
  alarm(1);
  // But also use the epoll_pwait to modify the signal mask.
  epoll_pwait(epfd, &ev, 1, 5000, &sigmask);
  test_assert(errno == EINTR);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
