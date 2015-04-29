/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  pid_t sid = getsid(0);
  atomic_printf("getsid(0) session ID: %d\n", sid);
  test_assert(sid > 0);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
