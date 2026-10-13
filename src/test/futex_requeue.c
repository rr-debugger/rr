/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int v;
static volatile int v2;
static int other;

static int saw_v2_equals_1;
static int saw_v2_equals_2;

static void* run_thread(__attribute__((unused)) void* p) {
  test_assert(0 ==
              syscall(SYS_futex, &v, FUTEX_WAIT, 0, (void*)0, (void*)0, 0));
  if (v2 == 1) {
    __sync_fetch_and_add(&saw_v2_equals_1, 1);
  } else if (v2 == 2) {
    __sync_fetch_and_add(&saw_v2_equals_2, 1);
  }
  return NULL;
}

/* Wait until n threads wait on v. To count them, requeue them all to another
   futex and back. */
static void wait_for_waiters(int n) {
  while (1) {
    int count = syscall(SYS_futex, &v, FUTEX_REQUEUE, 0, INT_MAX, &other, 0);
    test_assert(count ==
                syscall(SYS_futex, &other, FUTEX_REQUEUE, 0, INT_MAX, &v, 0));
    if (count == n) {
      return;
    }
    test_assert(count < n);
    sched_yield();
  }
}

static int threads_done(void) {
  return __sync_fetch_and_add(&saw_v2_equals_1, 0) +
         __sync_fetch_and_add(&saw_v2_equals_2, 0);
}

int main(void) {
  pthread_t thread1, thread2, thread3;
  int i;

  v = 0;
  v2 = 1;
  pthread_create(&thread1, NULL, run_thread, NULL);
  pthread_create(&thread2, NULL, run_thread, NULL);
  pthread_create(&thread3, NULL, run_thread, NULL);

  wait_for_waiters(3);

  // Wake one thread, and requeue one thread onto v2.
  test_assert(2 == syscall(SYS_futex, &v, FUTEX_REQUEUE, 1, 1, &v2, 0));
  // Let the woken thread see v2 == 1.
  while (threads_done() < 1) {
    sched_yield();
  }

  test_assert(-1 == syscall(SYS_futex, &v, FUTEX_CMP_REQUEUE, 1, 1, &v2, 42));
  test_assert(EAGAIN == errno);

  // Requeue the remaining thread onto v2.
  test_assert(1 == syscall(SYS_futex, &v, FUTEX_REQUEUE, 0, 1, &v2, 0));
  // That must not have woken the thread. If it did, give the thread a chance
  // to run and see v2 == 1, which the checks below catch.
  for (i = 0; i < 10; ++i) {
    sched_yield();
  }

  ++v2;
  // Wake both threads.
  test_assert(2 ==
              syscall(SYS_futex, &v2, FUTEX_CMP_REQUEUE, 2, INT_MAX, &v, 2));

  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);
  pthread_join(thread3, NULL);

  test_assert(saw_v2_equals_1 == 1);
  test_assert(saw_v2_equals_2 == 2);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
