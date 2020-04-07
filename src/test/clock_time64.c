/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct rr_timespec64 {
  int64_t tv_sec;
  int64_t tv_nsec;
};

int main(void) {
  struct rr_timespec64 ts;
  struct rr_timespec64 duration = { 0, 1000000 };

  if (sizeof(void*) != 4) {
    atomic_puts("Ignoring non-32bit test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  int ret = syscall(RR_clock_getres_time64, CLOCK_MONOTONIC, &ts);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("Skipping tests, because 64 bit time syscalls are unavailable");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == ret);
  atomic_printf("Clock resolution %lld %lld\n", (long long)ts.tv_sec, (long long)ts.tv_nsec);

  test_assert(0 == syscall(RR_clock_gettime64, CLOCK_MONOTONIC, &ts));
  atomic_printf("Clock now %lld %lld\n", (long long)ts.tv_sec, (long long)ts.tv_nsec);

  test_assert(0 == syscall(RR_clock_nanosleep_time64, CLOCK_MONOTONIC, 0, &duration, &ts));

  test_assert(0 == syscall(RR_clock_gettime64, CLOCK_MONOTONIC, &ts));
  atomic_printf("Clock now %lld %lld\n", (long long)ts.tv_sec, (long long)ts.tv_nsec);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
