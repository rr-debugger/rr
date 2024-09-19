/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

/* Given command-line parameter <c>,
   test fails if sysconf() reports 'c' cores. */

int main(__attribute__((unused)) int argc, char** argv) {
  int cores = atoi(argv[1]);
  int sysconf_onln = sysconf(_SC_NPROCESSORS_ONLN);

  if (sysconf_onln == cores) {
    caught_test_failure("got core count: %d", cores);
  }

  atomic_printf("Found %d cores online\n", sysconf_onln);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
