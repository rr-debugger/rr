/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  char* tty = ttyname(STDIN_FILENO);
  atomic_printf("ttyname = %s\n", tty);
  if (!tty) {
    atomic_puts("No tty attached to stdin");
    fputs("EXIT-SUCCESS", stderr);
    return 0;
  }
  int fd = open(tty, O_RDWR);
  test_assert(13 == write(fd, "EXIT-SUCCESS\n", 13));
  return 0;
}
