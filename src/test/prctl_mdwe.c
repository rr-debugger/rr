/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret = prctl(PR_GET_MDWE, 0, 0, 0, 0);
  if (ret == -1 && errno == EINVAL) {
    atomic_puts("PR_GET_MDWE not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret >= 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
