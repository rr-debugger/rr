/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  int fd = open("/dev/tty", O_RDWR);
  test_assert(fd >= 0);
  test_assert(13 == write(fd, "EXIT-SUCCESS\n", 13));
  return 0;
}
