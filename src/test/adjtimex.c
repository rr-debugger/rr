/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <sys/timex.h>
#include <time.h>

int main(void) {
  struct timex tx;
  memset(&tx, 0, sizeof(tx));
  test_assert(-1 != adjtimex(&tx));

  struct timespec ts;
  memset(&ts, 0, sizeof(ts));

  test_assert(0 == clock_gettime(CLOCK_REALTIME, &ts));

  // Verify that adjtimex() and clock_gettime() return roughly the same time.
  test_assert(labs(tx.time.tv_sec - ts.tv_sec) <= 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
