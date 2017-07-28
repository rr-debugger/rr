/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Keep this roughly in sync with 'clock_nanosleep' */

static void* do_thread(__attribute__((unused)) void* p) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGINT);
  pthread_sigmask(SIG_BLOCK, &sigs, NULL);

  while (1) {
    sleep(1);
    test_assert(0 == kill(getpid(), SIGINT));
  }
  return NULL;
}

static void handler(__attribute__((unused)) int sig) {}

int main(void) {
  struct timespec sleep = { 0, 1000000 };
  struct timespec* remain;
  pthread_t thread;

  test_assert(0 == nanosleep(&sleep, NULL));

  ALLOCATE_GUARD(remain, 'x');
  remain->tv_sec = 9999;
  remain->tv_nsec = 9998;
  test_assert(0 == nanosleep(&sleep, remain));
  VERIFY_GUARD(remain);
  test_assert(remain->tv_sec == 9999 && remain->tv_nsec == 9998);

  test_assert(0 == signal(SIGINT, handler));
  pthread_create(&thread, NULL, do_thread, NULL);

  sleep.tv_sec = 1000000;
  test_assert(-1 == nanosleep(&sleep, remain));
  test_assert(errno == EINTR);
  VERIFY_GUARD(remain);
  test_assert(remain->tv_sec <= sleep.tv_sec);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
