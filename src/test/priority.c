/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int prio1, prio2;

  prio1 = getpriority(PRIO_PROCESS, 0);
  atomic_printf("Current process priority: %d\n", prio1);
  if (prio1 < 19) {
    /* If it's less than 19, we can decrease the
     * priority. */
    ++prio1;
  }

  setpriority(PRIO_PROCESS, 0, prio1);

  prio2 = getpriority(PRIO_PROCESS, 0);
  test_assert(prio1 == prio2);
  atomic_printf("Now priority is: %d\n", prio2);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
