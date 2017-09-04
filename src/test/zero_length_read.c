/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  char buf[1024];
  ssize_t count = read(STDIN_FILENO, &buf[0], 0);
  test_assert(count == 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
