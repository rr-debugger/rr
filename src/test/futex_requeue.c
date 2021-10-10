/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int v;
static volatile int v2;

static volatile int saw_v2_equals_1;
static volatile int saw_v2_equals_2;

static void* run_thread(__attribute__((unused)) void* p) {
  test_assert(0 == syscall(SYS_futex, &v, FUTEX_WAIT, 0, (void*)0, (void*)0, 0));
  if (v2 == 1) {
    ++saw_v2_equals_1;
  } else if (v2 == 2) {
    ++ saw_v2_equals_2;
  }
  return NULL;
}

int main(void) {
  pthread_t thread1, thread2, thread3;

  v = 0;
  v2 = 1;
  pthread_create(&thread1, NULL, run_thread, NULL);
  pthread_create(&thread2, NULL, run_thread, NULL);
  pthread_create(&thread3, NULL, run_thread, NULL);

  // Give all the threads a chance to block.
  usleep(500000);

  // Wake one thread, and requeue one thread onto v2.
  test_assert(2 == syscall(SYS_futex, &v, FUTEX_REQUEUE, 1, 1, &v2, 0));
  usleep(250000);

  test_assert(-1 == syscall(SYS_futex, &v, FUTEX_CMP_REQUEUE, 1, 1, &v2, 42));
  test_assert(EAGAIN == errno);

  // Requeue the remaining thread onto v2.
  test_assert(1 == syscall(SYS_futex, &v, FUTEX_REQUEUE, 0, 1, &v2, 0));
  usleep(250000);

  ++v2;
  // Wake both threads.
  test_assert(2 == syscall(SYS_futex, &v2, FUTEX_CMP_REQUEUE, 2, INT_MAX, &v, 2));

  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);
  pthread_join(thread3, NULL);

  test_assert(saw_v2_equals_1 == 1);
  test_assert(saw_v2_equals_2 == 2);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
