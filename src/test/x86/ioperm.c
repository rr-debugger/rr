/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret;
  ret = syscall(SYS_ioperm, 0, 1024, 1);
  atomic_printf("ioperm returned %d\n", ret);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
