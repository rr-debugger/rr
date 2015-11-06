/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {

  uid_t real = getuid();

  test_assert(0 == setuid(real));

  // We can't rely on the presence of any specific user, except for the
  // current one. But the kernel returns EINVAL for -1, see
  // include/linux/uidgid.h:uid_valid()
  // Use that value to increase scope of testing.
  test_assert(-1 == setuid((uid_t)-1));

  test_assert(0 == setuid(real));
  test_assert(real == getuid());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
