/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <linux/usbdevice_fs.h>

/* When USBDEVFS_REAPURB(NDELAY) fails (e.g. EAGAIN when no URB is ready),
   the kernel does not write the output URB pointer. Check that rr doesn't
   clobber it either. A non-usbdevfs fd takes the same path in rr and fails
   with ENOTTY, so no USB device is needed. */
static void check_reap(int fd, unsigned long cmd, uintptr_t sentinel) {
  void* urb = (void*)sentinel;
  int ret = ioctl(fd, cmd, &urb);
  test_assert(ret == -1);
  test_assert(urb == (void*)sentinel);
}

int main(void) {
  int fd = open("/dev/null", O_RDONLY);
  test_assert(fd >= 0);

  check_reap(fd, USBDEVFS_REAPURBNDELAY, 0x12345678);
  check_reap(fd, USBDEVFS_REAPURBNDELAY, 0x87654321);
  check_reap(fd, USBDEVFS_REAPURB, 0x12345678);
  check_reap(fd, USBDEVFS_REAPURB, 0x87654321);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
