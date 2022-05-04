/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  struct timeval tv;
  for (i = 0; i < 160000; ++i) {
    gettimeofday(&tv, NULL);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
