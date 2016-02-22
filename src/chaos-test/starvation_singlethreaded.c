/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

static double samples[10000000];
static size_t sample_count = 0;

/* Given command-line parameters <S>, <T>, <D> and <L>:
   Spins the CPU on a single thread until L microseconds have elapsed.
   The test fails if, at some point starting between S and T microseconds,
   we fail to be scheduled for D microseconds */

int main(__attribute__((unused)) int argc, char** argv) {
  double start = now_double();
  double S = atoi(argv[1]) / 1000000.0 + start;
  double T = atoi(argv[2]) / 1000000.0 + start;
  double D = atoi(argv[3]) / 1000000.0;
  double L = atoi(argv[4]) / 1000000.0 + start;
  int k = 0;
  double last = 0;

  atomic_printf("Critical range is %f to %f\n", S, T);

  while (1) {
    int i;
    double t;
    for (i = 0; i < 10000; ++i) {
      k += i * i;
    }
    t = now_double();
    samples[sample_count++] = t;
    if (sample_count >= sizeof(samples) / sizeof(samples[0])) {
      atomic_puts("OVERFLOW");
      exit(1);
    }
    if (t > L) {
      break;
    }
    if (last >= S && last < T && t >= last + D) {
      caught_test_failure("time wasn't checked between %f and %f", last - start,
                          t - start);
    }
    last = t;
  }

  atomic_printf("dummy = %d\n", k);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
