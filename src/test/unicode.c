/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {}

static void outer(__attribute__((unused)) char* arg) {
  /* On some gdb/distro combinations, function parameters don't have
     correct debuginfo when stopped at a breakpoint on the function
     itself. So stop in `breakpoint()` and then use `finish` to return
     to this stack frame at a point where `arg` is sure to print
     correctly. */
  breakpoint();
}

int main(void) {
  outer("\xf0\x9d\x95\xa8\xc4\x81\xe2\x89\xa5\x33");
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
