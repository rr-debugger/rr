/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  pid_t sid1;
  pid_t sid2;

  sid1 = getsid(0);
  atomic_printf("getsid(0) session ID: %d\n", sid1);
  test_assert(sid1 > 0);
  sid2 = getsid(sid1);
  atomic_printf("getsid(getsid(0)) session ID: %d\n", sid2);
  test_assert(sid2 > 0);
  test_assert(sid1 == sid2);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
