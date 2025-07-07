/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <linux/serial.h>

int main(void) {
  int fd;
  int* mbits;
  struct serial_icounter_struct* sicnt;
  int* lsr;

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

  ALLOCATE_GUARD(sicnt, 'b');
  test_assert(0 == ioctl(fd, TIOCGICOUNT, sicnt));
  VERIFY_GUARD(sicnt);
  atomic_printf("TIOCGICOUNT returned %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d\n",
                sicnt->cts, sicnt->dsr, sicnt->rng, sicnt->dcd, sicnt->rx, sicnt->tx,
                sicnt->frame, sicnt->overrun, sicnt->parity, sicnt->brk, sicnt->buf_overrun);

  ALLOCATE_GUARD(lsr, 'c');
  test_assert(0 == ioctl(fd, TIOCSERGETLSR, lsr));
  VERIFY_GUARD(lsr);
  atomic_printf("TIOCSERGETLSR returned lsr=0x%x\n", *lsr);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
