/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define RR_P_PIDFD 3

int main(void) {
  int child;
  int pipe_fds[2];
  int pidfd;

  pipe(pipe_fds);
  child = fork();
  if (!child) {
    char ch;
    read(pipe_fds[0], &ch, 1);
    return 77;
  }

  pidfd = syscall(RR_pidfd_open, child, 0);
  write(pipe_fds[1], "x", 1);
  if (pidfd < 0 && errno == ENOSYS) {
    int status;
    atomic_puts("pidfd_open not supported, skipping test");
    test_assert(wait(&status) == child);
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  } else {
    siginfo_t info;
    test_assert(pidfd >= 0);
    test_assert(waitid(RR_P_PIDFD, pidfd, &info, WEXITED) == 0);
    test_assert(info.si_pid == child);
    test_assert(info.si_code == CLD_EXITED);
    test_assert(info.si_status == 77);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
