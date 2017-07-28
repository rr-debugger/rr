/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct timespec ts = { 1000000, 0 };

  atomic_puts("sleeping");

  nanosleep(&ts, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 1;
}
