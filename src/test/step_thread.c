/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

pthread_barrier_t bar;

/* NB: these must *not* be macros so that debugger step-next works as
 * expected per the program source. */
static void A(void) {
  pthread_barrier_wait(&bar); // Barrier 3
  pthread_barrier_wait(&bar); // Barrier 4
}
static void B(void) {
  pthread_barrier_wait(&bar); // Barrier 3
  pthread_barrier_wait(&bar); // Barrier 4
}

static void* threadA(__attribute__((unused)) void* unused) {
  pthread_barrier_wait(&bar); // Barrier 1
  pthread_barrier_wait(&bar); // Barrier 2
  A();
  return NULL;
}
static void* threadB(__attribute__((unused)) void* unused) {
  pthread_barrier_wait(&bar); // Barrier 1
  pthread_barrier_wait(&bar); // Barrier 2
  B();
  return NULL;
}

static void C(void) {
  pthread_barrier_wait(&bar); // Barrier 3
}

static void hit_barrier(void) {
  int break_here = 1;
  (void)break_here;
  atomic_puts("hit barrier");
}

static void ready(void) {
  int break_here = 1;
  (void)break_here;
}

int main(void) {
  pthread_t a, b;

  pthread_barrier_init(&bar, NULL, 3);

  pthread_create(&a, NULL, threadA, NULL);
  pthread_create(&b, NULL, threadB, NULL);

  pthread_barrier_wait(&bar); // Barrier 1

  ready();

  pthread_barrier_wait(&bar); // Barrier 2

  C();
  hit_barrier();

  pthread_barrier_wait(&bar); // Barrier 4

  pthread_join(a, NULL);
  pthread_join(b, NULL);

  return 0;
}
