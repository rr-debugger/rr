/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

void spin(void) {
  int i;

  atomic_puts("spinning");
  for (i = 1; i < (1 << 30); ++i) {
    if (0 == i % (1 << 20)) {
      write(STDOUT_FILENO, ".", 1);
    }
    if (0 == i % (79 * (1 << 20))) {
      write(STDOUT_FILENO, "\n", 1);
    }
  }
}

int main(void) {
  spin();
  atomic_puts("done");
  return 0;
}
