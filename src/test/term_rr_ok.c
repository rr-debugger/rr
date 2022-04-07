/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {
  exit(0);
}

int main(void) {
  signal(SIGTERM, handler);
  atomic_puts("EXIT-SUCCESS");
  kill(getppid(), SIGTERM);
  sleep(10000);
  return 0;
}
