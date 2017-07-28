/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define RR_MEMBARRIER_CMD_QUERY 0
#define RR_MEMBARRIER_CMD_SHARED 1

int main(void) {
  int ret = syscall(RR_membarrier, RR_MEMBARRIER_CMD_QUERY, 0);
  if (ret < 0 && errno == ENOSYS) {
    atomic_puts("membarrier not supported, skipping test");
  } else {
    test_assert(ret >= 0);
    if (ret & RR_MEMBARRIER_CMD_SHARED) {
      test_assert(0 == syscall(RR_membarrier, RR_MEMBARRIER_CMD_SHARED, 0));
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
