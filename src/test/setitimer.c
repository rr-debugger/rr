/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct itimerval* v1;
  struct itimerval* v2;
  struct itimerval* v3;

  ALLOCATE_GUARD(v1, 0);
  v1->it_interval.tv_sec = 10000;
  v1->it_interval.tv_usec = 0;
  v1->it_value.tv_sec = 10000;
  v1->it_value.tv_usec = 0;
  test_assert(0 == setitimer(ITIMER_REAL, v1, NULL));
  VERIFY_GUARD(v1);

  ALLOCATE_GUARD(v2, 1);
  test_assert(0 == setitimer(ITIMER_REAL, v1, v2));
  test_assert(v2->it_interval.tv_sec == v1->it_interval.tv_sec);
  VERIFY_GUARD(v2);

  ALLOCATE_GUARD(v3, 2);
  test_assert(0 == getitimer(ITIMER_REAL, v3));
  test_assert(v3->it_interval.tv_sec == v1->it_interval.tv_sec);
  VERIFY_GUARD(v3);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
