/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  pid_t child = 0;

  atomic_puts("doing dummy PTRACE_ATTACH operation ...");

  ptrace(PTRACE_ATTACH, child, 0, 0);
  test_assert("Not reached" && 0);

  return 0;
}
