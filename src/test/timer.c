/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static volatile int caught_sig = 0;

void catcher(int signum, __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = signum;
}

int main(void) {
  timer_t* id;
  struct itimerspec its = { { 100000, 0 }, { 0, 100000000 } };
  struct itimerspec its2 = { { 100000, 0 }, { 100000, 0 } };
  struct itimerspec* old;
  struct itimerspec* old2;
  struct sigaction sact;
  int counter;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

  ALLOCATE_GUARD(id, 'a');
  test_assert(0 == timer_create(CLOCK_REALTIME, NULL, id));
  VERIFY_GUARD(id);

  test_assert(0 == timer_settime(*id, 0, &its, NULL));

  for (counter = 0; counter >= 0 && !caught_sig; counter++) {
    if (counter % 100000 == 0) {
      write(STDOUT_FILENO, ".", 1);
    }
  }

  atomic_printf("\nSignal %d caught, Counter is %d\n", caught_sig, counter);
  test_assert(SIGALRM == caught_sig);

  test_assert(0 == timer_getoverrun(*id));

  ALLOCATE_GUARD(old, 'b');
  test_assert(0 == timer_settime(*id, 0, &its2, old));
  VERIFY_GUARD(old);
  test_assert(old->it_interval.tv_sec == its.it_interval.tv_sec);
  test_assert(old->it_interval.tv_nsec == its.it_interval.tv_nsec);
  test_assert(old->it_value.tv_sec <= its.it_interval.tv_sec);
  test_assert(old->it_value.tv_sec >= its.it_interval.tv_sec / 2);
  test_assert(old->it_value.tv_nsec < 1000000000);

  ALLOCATE_GUARD(old2, 'c');
  test_assert(0 == timer_gettime(*id, old2));
  VERIFY_GUARD(old2);
  test_assert(old2->it_interval.tv_sec == its2.it_interval.tv_sec);
  test_assert(old2->it_interval.tv_nsec == its2.it_interval.tv_nsec);
  test_assert(old2->it_value.tv_sec <= its2.it_interval.tv_sec);
  test_assert(old2->it_value.tv_sec >= its2.it_interval.tv_sec / 2);
  test_assert(old2->it_value.tv_nsec < 1000000000);

  test_assert(0 == timer_delete(*id));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
