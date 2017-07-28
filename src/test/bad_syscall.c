/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret = syscall(-10);
  test_assert(-1 == ret && ENOSYS == errno);
  ret = syscall(9999);
  test_assert(-1 == ret && ENOSYS == errno);
  atomic_puts("EXIT-SUCCESS");
  return ret;
}
