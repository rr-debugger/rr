/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  uint32_t ftx;
  int ret = syscall(SYS_futex, &ftx, 0x70, 0, NULL, NULL, 0);
  test_assert(ret < 0);
  test_assert(errno == ENOSYS);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
