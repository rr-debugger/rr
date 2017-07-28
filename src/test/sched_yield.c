/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

enum { PING, PONG } last;

pthread_once_t init_once = PTHREAD_ONCE_INIT;
static void init_ping(void) { last = PONG; }
static void init_pong(void) { last = PING; }

static pthread_barrier_t bar;

static int ping_ready;
static int pong_ready;

static void ping_pong(int which) {
  volatile int* self_ready = which == PING ? &ping_ready : &pong_ready;
  volatile int* other_ready = which == PING ? &pong_ready : &ping_ready;
  int i;

  /* Efficiently wait for the other thread to arrive. */
  pthread_barrier_wait(&bar);

  /* Semi-busy-wait for both threads to be runnable.  (One
   * thread exiting a barrier doesn't guarantee that the other
   * thread is immediately runnable.) */
  *self_ready = 1;
  do {
    sched_yield();
  } while (!*other_ready);
  /* Whichever thread reaches this loop first initializes the
   * other to be "last". */
  pthread_once(&init_once, which == PING ? init_ping : init_pong);
  for (i = 0; i < 50; ++i) {
    /* Ensure that the other thread was the last to run
     * the loop body. */
    which == PING ? test_assert("ping thread: " && PONG == last)
                  : test_assert("pong thread: " && PING == last);
    last = which;
    /* Schedule the other thread run the next loop
     * iteration.
     *
     * NB: because the kernel scheduler is far more
     * complicated than rr's, this simplistic assumption
     * won't hold.  If rr's scheduler grows to that level
     * of complexity, it's probably best to remove this
     * test. */
    sched_yield();
  }
}

static void* pong_thread(__attribute__((unused)) void* unused) {
  ping_pong(PONG);
  return NULL;
}

int main(void) {
  cpu_set_t cpus;
  pthread_t t;

  CPU_ZERO(&cpus);
  CPU_SET(0, &cpus);
  sched_setaffinity(0, sizeof(cpus), &cpus);

  pthread_barrier_init(&bar, NULL, 2);

  test_assert(0 == pthread_create(&t, NULL, pong_thread, NULL));

  ping_pong(PING);

  pthread_join(t, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
