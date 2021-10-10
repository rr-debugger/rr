/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  /* Do several variations of invalid execs */
#pragma GCC diagnostic ignored "-Wnonnull"
  test_assert(-1 == execve(NULL, NULL, NULL));
  test_assert(errno == EFAULT);
  test_assert(-1 == execve("/proc/self/exe", (void*)0xdeadbeef, NULL));
  test_assert(errno == EFAULT);
  char *argv[] = { (char*)0xdeadbeef, NULL };
  test_assert(-1 == execve("/proc/self/exe", argv, NULL));
  test_assert(errno == EFAULT);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
