/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int count;

static void handler(__attribute__((unused)) int sig) { ++count; }

int main(void) {
  struct itimerval itv = {
    { 0, 1000 },
    { 0, 1000 },
  };

  test_assert(0 == signal(SIGPROF, handler));
  test_assert(0 == signal(SIGALRM, handler));

  setitimer(ITIMER_REAL, &itv, NULL);
  setitimer(ITIMER_PROF, &itv, NULL);

  while (count < 2000) {
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
