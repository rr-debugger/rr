/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A thread exits holding a robust mutex while the main thread is blocked in
   pthread_mutex_lock() on it. The kernel marks the mutex FUTEX_OWNER_DIED
   and wakes the main thread, whose lock returns EOWNERDEAD. */

static pthread_mutex_t mutex;
static int thread_locked;

static void* run_thread(void* p) {
  pid_t main_tid = (pid_t)(uintptr_t)p;

  test_assert(main_tid > 1);
  test_assert(0 == pthread_mutex_lock(&mutex));
  __atomic_store_n(&thread_locked, 1, __ATOMIC_SEQ_CST);
  /* The main thread sleeps only in its pthread_mutex_lock(). */
  while (get_task_state(main_tid) != 'S') {
    sched_yield();
  }
  return NULL;
}

int main(void) {
  pthread_mutexattr_t attr;
  pthread_t thread;
  pid_t main_tid;

  test_assert(0 == pthread_mutexattr_init(&attr));
  test_assert(0 == pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
  test_assert(0 == pthread_mutex_init(&mutex, &attr));

  main_tid = sys_gettid();
  test_assert(0 == pthread_create(&thread, NULL, run_thread,
                                  (void*)(uintptr_t)main_tid));

  while (!__atomic_load_n(&thread_locked, __ATOMIC_SEQ_CST)) {
    sched_yield();
  }
  test_assert(EOWNERDEAD == pthread_mutex_lock(&mutex));
  test_assert(0 == pthread_mutex_consistent(&mutex));
  test_assert(0 == pthread_mutex_unlock(&mutex));
  test_assert(0 == pthread_join(thread, NULL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
