/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  // Test invalid fd -1, to make sure that rr doesn't accidentally think
  // this is it's desched fd (esp. when syscallbuf is disabled).
  test_assert(-1 == ioctl(-1, PERF_EVENT_IOC_ENABLE));
  test_assert(errno == EBADF);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
