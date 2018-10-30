/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret = acct("this_file_does_not_exist.1903901");
  test_assert(ret < 0 && (errno == EPERM || errno == ENOENT));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
