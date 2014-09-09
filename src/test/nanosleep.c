/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  test_assert(argc == 2);

  int sleep_secs = atoi(argv[1]);
  struct timespec ts = { .tv_sec = sleep_secs };

  atomic_puts("sleeping");

  nanosleep(&ts, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 1;
}
