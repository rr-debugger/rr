/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  gid_t gid = getgid();
  int err = setgid(gid);
  atomic_printf("setgid returned: %d\n", err);
  test_assert(0 == err);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
