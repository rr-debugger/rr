/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handle_SIGTERM(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

int main(void) {
  struct timespec ts = { 1000000, 0 };

  signal(SIGTERM, handle_SIGTERM);
  atomic_puts("sleeping");

  nanosleep(&ts, NULL);
  atomic_puts("FAILED");
  return 1;
}
