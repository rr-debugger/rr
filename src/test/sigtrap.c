/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handle_sigtrap(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
  _exit(0);
}

int main(void) {
  signal(SIGTRAP, handle_sigtrap);

  atomic_puts("raising SIGTRAP ...");

  raise(SIGTRAP);

  return 0;
}
