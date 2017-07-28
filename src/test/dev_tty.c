/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("/dev/tty", O_RDWR);
  if (fd == -1 && errno == ENXIO) {
    atomic_puts("/dev/tty does not exist, skipping test");
    fd = STDERR_FILENO;
  } else {
    test_assert(fd >= 0);
  }
  test_assert(13 == write(fd, "EXIT-SUCCESS\n", 13));
  return 0;
}
