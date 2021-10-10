/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define RR_IOPRIO_WHO_PROCESS 1
#define RR_IOPRIO_CLASS_IDLE 3
#define RR_IOPRIO_CLASS_SHIFT 13

int main(void) {
  int ret;
  ret = syscall(RR_ioprio_get, RR_IOPRIO_WHO_PROCESS, 0);
  test_assert(ret >= 0);
  ret = syscall(RR_ioprio_set, RR_IOPRIO_WHO_PROCESS, 0, RR_IOPRIO_CLASS_IDLE << RR_IOPRIO_CLASS_SHIFT);
  test_assert(ret >= 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
