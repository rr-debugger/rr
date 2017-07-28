/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  volatile int* p = NULL;
  *p = 42;
  test_assert("Not reached" && 0);
  return 0;
}
