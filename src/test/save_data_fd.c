/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define DEV_RANDOM "/dev/urandom"

int main(void) {
  int fd = open(DEV_RANDOM, O_RDONLY);
  char buf[128];
  ssize_t nread;

  test_assert(0 <= fd);

  nread = read(fd, buf, sizeof(buf));
  atomic_printf("Read %zd random bytes (expected %zu)\n", nread, sizeof(buf));
  test_assert(nread == sizeof(buf));

  check_data(buf, sizeof(buf));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
