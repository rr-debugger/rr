/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  int ret = syscall(-10);
  test_assert(-1 == ret && ENOSYS == errno);
  return 0;
}
