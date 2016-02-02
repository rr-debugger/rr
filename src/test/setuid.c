/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#include <sys/types.h>
#include <unistd.h>

int main(void) {
  uid_t orig;
  uid_t new;
  int ret;

  orig = getuid();
  test_assert(0 == setuid(orig));
  new = orig + 1;
  ret = setuid(new);
  if (ret == -1) {
    test_assert(errno == EPERM);
    atomic_puts("Test did nothing because process does not have CAP_SETUID?");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  } else {
    test_assert(getuid() == new);
  }
  atomic_puts("EXIT-SUCCESS");

  return 0;
}
