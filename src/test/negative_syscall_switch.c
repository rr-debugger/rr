/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The kernel skips a syscall with a negative number after its seccomp stop.
   rr must record that syscall's entry before it runs another thread, so that
   the main thread's store to `flag` is ordered before what do_thread does
   after reading it. The .run file uses --always-switch so that rr switches
   threads wherever it allows a switch. */

static int thread_running;
static int flag;

static void* do_thread(__attribute__((unused)) void* p) {
  __atomic_store_n(&thread_running, 1, __ATOMIC_RELEASE);
  while (!__atomic_load_n(&flag, __ATOMIC_ACQUIRE)) {
    sched_yield();
  }
  /* do_thread's first event after it reads `flag` is the entry of this
     unbuffered syscall. */
  unbufferable_syscall(RR_getpid, 0, 0, 0);
  return NULL;
}

int main(void) {
  for (int i = 0; i < 20; ++i) {
    pthread_t thread;
    __atomic_store_n(&thread_running, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flag, 0, __ATOMIC_RELAXED);
    test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));
    while (!__atomic_load_n(&thread_running, __ATOMIC_ACQUIRE)) {
      sched_yield();
    }
    if (i & 1) {
      /* One more syscall stop of the main thread changes whether rr has
         stopped do_thread inside sched_yield() or after it returned when
         the main thread makes the negative syscall. */
      unbufferable_syscall(RR_getpid, 0, 0, 0);
    }
    __atomic_store_n(&flag, 1, __ATOMIC_RELEASE);
    test_assert(-1 == syscall(-10) && ENOSYS == errno);
    test_assert(0 == pthread_join(thread, NULL));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
