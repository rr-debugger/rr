/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int num_its;

static void syscall_spam(void) {
  int i;
  struct timespec ts;
  struct timeval tv;
  for (i = 0; i < 1 << num_its; ++i) {
    /* The odds of the signal being caught in the library
     * implementing these syscalls is very high.  But even
     * if it's not caught there, this test will pass. */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    gettimeofday(&tv, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    gettimeofday(&tv, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    gettimeofday(&tv, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    gettimeofday(&tv, NULL);
  }
}

static void unblock_signals(void) {
  sigset_t set;
  sigfillset(&set);
  test_assert(0 == pthread_sigmask(SIG_UNBLOCK, &set, NULL));
  atomic_printf("  %d: unblocked all sigs\n", sys_gettid());
}

static void* thread(__attribute__((unused)) void* unused) {
  unblock_signals();
  syscall_spam();
  return NULL;
}

int main(int argc, char** argv) {
  sigset_t set;
  pthread_t t;

  test_assert(argc == 2);
  num_its = atoi(argv[1]);
  test_assert(num_its > 0);

  atomic_printf("Running 2^%d iterations in two threads\n", num_its);

  atomic_printf("parent %d: blocking all sigs ...\n", getpid());
  sigfillset(&set);
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &set, NULL));

  pthread_create(&t, NULL, thread, NULL);

  unblock_signals();
  syscall_spam();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
