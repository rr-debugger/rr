/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i = 0;
  pid_t pid;
  int status;
  siginfo_t si;

  ++i;
  pid = fork();
  if (!pid) {
    usleep(100);
    exit(i);
  }
  test_assert(pid == wait(&status));
  atomic_printf("%d exited with status %#x\n", pid, status);
  test_assert(WIFEXITED(status) && i == WEXITSTATUS(status));

  ++i;
  pid = fork();
  if (!pid) {
    usleep(100);
    exit(i);
  }
  test_assert(pid == waitpid(pid, &status, 0));
  atomic_printf("%d exited with status %#x\n", pid, status);
  test_assert(WIFEXITED(status) && i == WEXITSTATUS(status));

  ++i;
  pid = fork();
  if (!pid) {
    usleep(100);
    exit(i);
  }
  test_assert(0 == waitid(P_PID, pid, &si, WEXITED | WSTOPPED));
  atomic_printf("%d exited with exit-type %d; code %d\n", si.si_pid, si.si_code,
                si.si_status);
  test_assert(SIGCHLD == si.si_signo && CLD_EXITED == si.si_code);
  test_assert(pid == si.si_pid && i == si.si_status);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
