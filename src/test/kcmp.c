/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t pid = getpid();
  int ret;

  ret = syscall(RR_kcmp, pid, pid, RR_KCMP_FILES, 0, 0);
  if (ret < 0 && errno == ENOSYS) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);
  test_assert(0 < syscall(RR_kcmp, pid, getppid(), RR_KCMP_FILES, 0, 0));
  test_assert(0 == syscall(RR_kcmp, pid, pid, RR_KCMP_FILE, STDIN_FILENO,
                           STDIN_FILENO));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
