/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

/* Given command-line parameter <c>,
   test fails if sched_getaffinity() reports 'c' cores. */

int main(__attribute__((unused)) int argc, char** argv) {
  int cores = atoi(argv[1]);
  int i;

  cpu_set_t cpus;
  int count = 0;
  sched_getaffinity(0, sizeof(cpus), &cpus);
  for (i = 0; i < CPU_SETSIZE; ++i) {
    if (CPU_ISSET(i, &cpus)) {
      ++count;
    }
  }

  if (count == cores) {
    caught_test_failure("got core count: %d", cores);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
