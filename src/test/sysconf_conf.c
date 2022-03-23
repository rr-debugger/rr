/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  long ncpus = sysconf(_SC_NPROCESSORS_CONF);
  unsigned cpu;
  int ret;

  atomic_printf("sysconf says %ld processors are configured\n", ncpus);
  ret = getcpu(&cpu, NULL);
  test_assert(ret == 0);
  test_assert(cpu < (unsigned)ncpus);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
