/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  char buf[32];
  int garbage_fd = 1 << 30;

  read(garbage_fd, buf, sizeof(buf));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
