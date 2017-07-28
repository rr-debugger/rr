/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void do_test(int fd) {
  uint64_t val = 7;
  uint64_t out;

  test_assert(fd >= 0);
  test_assert(sizeof(val) == write(fd, &val, sizeof(val)));
  test_assert(sizeof(out) == read(fd, &out, sizeof(out)));
  test_assert(out == val);
}

int main(void) {
  do_test(syscall(SYS_eventfd, 0));
  do_test(eventfd(0, 0));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
