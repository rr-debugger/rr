/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h), as a
 * software-ticks compiler pass would make it: rr records and replays it with
 * software ticks. Threads that only spin need tick traps to be preempted, and
 * a timer signal arrives at arbitrary points. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

#define TICK() RR_SOFTTICK()

static volatile int stop;
static volatile int sigs;

static void handler(__attribute__((unused)) int sig) {
  TICK();
  ++sigs;
}

static void* spin(void* arg) {
  long id = (long)arg;
  long local = 0;
  TICK();
  while (!stop) {
    TICK();
    ++local;
  }
  return (void*)(local + id);
}

static unsigned long fib(int n) {
  TICK();
  return n < 2 ? (unsigned long)n : fib(n - 1) + fib(n - 2);
}

int main(void) {
  pthread_t threads[2];
  struct itimerval timer = { { 0, 1000 }, { 0, 1000 } };
  struct itimerval off = { { 0, 0 }, { 0, 0 } };
  unsigned long f = 0;
  int i;
  /* Under rr's software ticks the tracer arms the countdown before resuming
   * us: its high word (on i386 the disarmed word) is 0. Natively, or with
   * the PMU, the countdown is parked and that word is not 0. */
  volatile uint32_t* countdown = (volatile uint32_t*)RR_SOFTTICKS_COUNTDOWN_ADDR;
  test_assert(countdown[1] == 0);

  TICK();
  signal(SIGALRM, handler);
  setitimer(ITIMER_REAL, &timer, NULL);
  for (i = 0; i < 2; ++i) {
    TICK();
    pthread_create(&threads[i], NULL, spin, (void*)(long)i);
  }
  for (i = 0; i < 5; ++i) {
    TICK();
    f += fib(22);
  }
  stop = 1;
  for (i = 0; i < 2; ++i) {
    TICK();
    pthread_join(threads[i], NULL);
  }
  setitimer(ITIMER_REAL, &off, NULL);
  test_assert(f == 5 * 17711);
  atomic_printf("signals: %d\n", sigs > 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
