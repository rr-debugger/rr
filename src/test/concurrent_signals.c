/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int stop;

static void handler(__attribute__((unused)) int sig) {}

static void term_handler(__attribute__((unused)) int sig) { stop = 1; }

int main(void) {
  test_assert(0 == signal(SIGUSR1, handler));
  test_assert(0 == signal(SIGUSR2, handler));
  test_assert(0 == signal(SIGTERM, term_handler));

  atomic_puts("ready");

  while (!stop) {}

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
