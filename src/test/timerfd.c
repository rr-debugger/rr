/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = timerfd_create(CLOCK_MONOTONIC, 0);
  struct itimerspec spec, old;
  uint64_t num_expirations;

  atomic_printf("created timerfd %d\n", fd);
  test_assert(fd >= 0);

  memset(&spec, 0, sizeof(spec));
  spec.it_value.tv_nsec = 100000000;
  atomic_printf("setting timer to expire in {sec:%ld,nsec:%ld}\n",
                spec.it_value.tv_sec, spec.it_value.tv_nsec);
  timerfd_settime(fd, 0, &spec, &old);

  atomic_printf("  (old expiration was {sec:%ld,nsec:%ld})\n",
                old.it_value.tv_sec, old.it_value.tv_nsec);
  test_assert(0 == old.it_value.tv_sec && 0 == old.it_value.tv_nsec);

  atomic_puts("sleeping 50ms ...");
  usleep(50000);

  timerfd_gettime(fd, &old);
  atomic_printf("  expiration now in {sec:%ld,nsec:%ld})\n",
                old.it_value.tv_sec, old.it_value.tv_nsec);
  test_assert(0 == old.it_value.tv_sec && old.it_value.tv_nsec <= 50000000);

  atomic_puts("waiting for timer to expire ...");
  read(fd, &num_expirations, sizeof(num_expirations));

  atomic_printf("  timer expired %" PRIu64 " times\n", num_expirations);
  test_assert(1 == num_expirations);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
