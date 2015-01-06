/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  test_assert(0 == prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
