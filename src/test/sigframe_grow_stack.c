/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handle_usr1(__attribute__((unused)) int sig) {}

static void recursive(int n) {
  char buf[1024];
  sprintf(buf, "hello %d", n);
  raise(SIGUSR1);
  if (n > 0) {
    recursive(n - 1);
  }
}

int main(void) {
  signal(SIGUSR1, handle_usr1);

  /* Consume about 1MB of stack. This should be fine. */
  recursive(1000);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
