/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  /* Do an invalid fcntl command on valid fd 0 */
  test_assert(-1 == fcntl(0, 9999));
  test_assert(errno == EINVAL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
