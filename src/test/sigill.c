/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void sighandler(int sig) {
  atomic_printf("caught signal %d, exiting\n", sig);
  atomic_puts("EXIT-SUCCESS");
  _exit(0);
}

int main(void) {
  signal(SIGILL, sighandler);

  atomic_puts("running undefined instruction ...");
  __asm__("ud2");
  test_assert("should have terminated!" && 0);
  return 0;
}
