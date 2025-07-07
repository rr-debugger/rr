/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;
  int* mbits;

  fd = open("/dev/ttyS0", O_RDWR);
  if (fd < 0) {
    atomic_puts("Can't open ttyS0, aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  ALLOCATE_GUARD(mbits, 'a');
  test_assert(0 == ioctl(fd, TIOCMGET, mbits));
  VERIFY_GUARD(mbits);
  atomic_printf("TIOCMGET returned mbits=0x%x\n", *mbits);
  test_assert(0 == ioctl(fd, TIOCMSET, mbits));
  atomic_printf("TIOCMSET mbits=0x%x afterwards\n", *mbits);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
