/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define RR_P_PIDFD 3

int main(void) {
  int child;
  int pipe_fds[2];
  int pidfd, gotfd;
  int status;
  char ch;

  pipe(pipe_fds);
  child = fork();
  if (!child) {
    kill(sys_gettid(), SIGSTOP);
    return 77;
  }

  test_assert(waitpid(child, &status, WUNTRACED) == child);
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  pidfd = syscall(RR_pidfd_open, child, 0);
  write(pipe_fds[1], "x", 1);
  if (pidfd < 0 && errno == ENOSYS) {
    atomic_puts("pidfd_open not supported, skipping test");
    kill(child, SIGCONT);
    test_assert(wait(&status) == child);
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(pidfd >= 0);

  gotfd = syscall(RR_pidfd_getfd, pidfd, pipe_fds[0], 0);
  if (gotfd < 0 && errno == ENOSYS) {
    atomic_puts("pidfd_getfd not supported, skipping test");
    kill(child, SIGCONT);
    test_assert(wait(&status) == child);
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(gotfd != pipe_fds[0]);
  read(gotfd, &ch, 1);
  test_assert(ch == 'x');

  // Test FileMonitors.
  gotfd = syscall(RR_pidfd_getfd, pidfd, 1, 0);
  test_assert(gotfd > 0);
  write(gotfd, "Hi\n", 3);

  kill(child, SIGCONT);
  test_assert(wait(&status) == child);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
