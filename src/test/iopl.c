/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret;
  ret = iopl(3);
  atomic_printf("iopl returned %d\n", ret);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
