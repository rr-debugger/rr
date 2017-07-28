/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, NULL);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL);
  }
  test_assert(ret == -1 && errno == EFAULT);

  test_assert(0 == prctl(PR_GET_SECCOMP));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
