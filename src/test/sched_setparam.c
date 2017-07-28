/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct sched_param* param;
  int scheduler;
  int min_priority;
  int max_priority;

  scheduler = sched_getscheduler(0);
  test_assert(scheduler >= 0);

  ALLOCATE_GUARD(param, 'x');
  test_assert(0 == sched_getparam(0, param));
  VERIFY_GUARD(param);

  min_priority = sched_get_priority_min(scheduler);
  test_assert(min_priority >= 0);
  max_priority = sched_get_priority_max(scheduler);
  test_assert(max_priority >= 0);
  test_assert(min_priority <= max_priority);

  param->sched_priority = min_priority;
  test_assert(0 == sched_setparam(0, param));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
