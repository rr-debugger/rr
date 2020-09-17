/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define RR_P_PIDFD 3

int main(void) {
  int child;
  int pipe_fds[2];
  int pidfd;
  int status;

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
    atomic_puts("pidfd_open not supported, skipping test");
    test_assert(wait(&status) == child);
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  } else {
    siginfo_t* info;
    int ret;
    test_assert(pidfd >= 0);
    ALLOCATE_GUARD(info, 'a');
    ret = waitid(RR_P_PIDFD, pidfd, info, WEXITED);
    VERIFY_GUARD(info);
    if (ret < 0 && errno == EINVAL) {
      atomic_puts("P_PIDFD not supported, skipping that part of the test");
      test_assert(wait(&status) == child);
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    } else {
      test_assert(ret == 0);
      test_assert(info->si_pid == child);
      test_assert(info->si_code == CLD_EXITED);
      test_assert(info->si_status == 77);

      ret = waitid(RR_P_PIDFD, 0, info, WEXITED);
      VERIFY_GUARD(info);
      test_assert(ret < 0);
      test_assert(errno == EBADF);

      ret = waitid(RR_P_PIDFD, INT_MAX, info, WEXITED);
      VERIFY_GUARD(info);
      test_assert(ret < 0);
      test_assert(errno == EBADF);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
