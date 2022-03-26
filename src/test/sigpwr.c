/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
}

int main(void) {
  signal(SIGPWR, handler);
  raise(SIGPWR);
  return 0;
}
