/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret = syscall(RR_userfaultfd, 0);
  test_assert(ret == -1 && errno == ENOSYS);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
