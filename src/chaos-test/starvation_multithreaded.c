/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

static double samples[10000000];
static size_t sample_count = 0;

/* Given command-line parameters <S>, <T>, <D> and <L>:
   Spin the CPU on one thread until L microseconds have elapsed, while
   other threads frequently sleep.
   The test fails if, at some point starting between S and T microseconds,
   the spinning thread fails to be scheduled for D microseconds. */

static double start, S, T, D, L;

static void* spinning_thread(__attribute__((unused)) void* p) {
  int k = 0;
  double last = 0;

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
  return (void*)(intptr_t)k;
}

static void* aux_thread(__attribute__((unused)) void* p) {
  /* Repeatedly sleep for a millisecond */
  struct timespec ts = { 0, 1000000 };
  while (1) {
    nanosleep(&ts, NULL);
  }
  return NULL;
}

int main(__attribute__((unused)) int argc, char** argv) {
  int i;
  pthread_t thread;

  start = now_double();
  S = atoi(argv[1]) / 1000000.0 + start;
  T = atoi(argv[2]) / 1000000.0 + start;
  D = atoi(argv[3]) / 1000000.0;
  L = atoi(argv[4]) / 1000000.0 + start;

  atomic_printf("Critical range is %f to %f\n", S, T);

  pthread_create(&thread, NULL, spinning_thread, NULL);

  for (i = 0; i < 4; ++i) {
    pthread_t t;
    pthread_create(&t, NULL, aux_thread, NULL);
  }

  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
