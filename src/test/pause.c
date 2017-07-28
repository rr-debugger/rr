/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int caught_signal;
static void handle_signal(__attribute__((unused)) int sig) { ++caught_signal; }

int main(void) {
  int err;

  signal(SIGALRM, handle_signal);
  alarm(1);
  atomic_puts("set alarm for 1 sec from now; pausing ...");
  pause();
  err = errno;

  atomic_printf("  ... woke up with errno %s(%d)\n", strerror(err), err);
  test_assert(1 == caught_signal);
  test_assert(EINTR == err);

  atomic_puts("EXIT-SUCCESS");
  return 1;
}
