/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int dummy;

static void do_some_ticks(void) {
  int i;
  for (i = 0; i < 1000; ++i) {
    dummy += i % 99;
  }
}

int main(void) {
  int i;

  for (i = 0; i < 100000; ++i) {
    do_some_ticks();
    int fd = open("/dev/null", O_RDONLY);
    close(fd);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
