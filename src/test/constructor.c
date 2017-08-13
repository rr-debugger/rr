/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

void lib_exit_success(void);

int main(void) {
  struct timespec ts = { 1, 0 };
  /* try patching clock_nanosleep, which a library thread is in */
  clock_nanosleep(CLOCK_MONOTONIC, 0, NULL, NULL);
  nanosleep(&ts, NULL);

  lib_exit_success();
  return 0;
}
