/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  aio_context_t ctx;
  int ret = syscall(__NR_io_setup, 1, &ctx);
  test_assert(ret < 0 && errno == ENOSYS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
