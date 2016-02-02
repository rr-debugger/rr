/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#include <sys/personality.h>

int main(void) {
  personality(PER_LINUX);
  test_assert(personality(0xffffffff) == PER_LINUX);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
