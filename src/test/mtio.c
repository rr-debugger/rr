/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct mtget out;
  int ret = ioctl(STDOUT_FILENO, MTIOCGET, &out);
  test_assert(ret == -1 && ENOTTY == errno);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
