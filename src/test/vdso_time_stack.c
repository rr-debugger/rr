/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  for (i = 0; i < 160000; ++i) {
    time(NULL);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
