/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret = syscall(RR_close_range, 1, UINT32_MAX, 0);
  test_assert(ret == -1 && errno == ENOSYS);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
