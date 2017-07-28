/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static int interrupted_sleep(void) {
  struct timespec ts = {.tv_sec = 2 };

  alarm(1);
  errno = 0;
  /* The implementation of sleep() is technically allowed to use
   * SIGALRM, so we have to use nanosleep() for pedantry. */
  nanosleep(&ts, NULL);
  return errno;
}

static int caught_signal;
static void handle_signal(__attribute__((unused)) int sig) {
  ++caught_signal;

  breakpoint();
  /* No more syscalls after here. */
}

int main(void) {
  int err;

  signal(SIGALRM, SIG_IGN);
  err = interrupted_sleep();
  atomic_printf("No sighandler; sleep exits with errno %d\n", err);
  test_assert(0 == err);

  signal(SIGALRM, handle_signal);
  err = interrupted_sleep();
  atomic_printf("With sighandler; sleep exits with errno %d\n", err);
  test_assert(1 == caught_signal);
  test_assert(EINTR == err);

  atomic_puts("EXIT-SUCCESS");
  return 1;
}
