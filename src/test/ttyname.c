/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  char* tty = ttyname(STDIN_FILENO);
  atomic_printf("ttyname = %s\n", tty);
  int fd = open(tty, O_RDWR);
  test_assert(13 == write(fd, "EXIT-SUCCESS\n", 13));
  return 0;
}
