/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;
  int vt;
  struct vt_stat vts;
  int tty_mode;

  fd = open("/dev/tty0", O_RDWR);
  if (fd < 0) {
    atomic_puts("Can't open tty, aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == ioctl(fd, VT_OPENQRY, &vt));
  atomic_printf("VT_OPENQRY returned %d\n", vt);

  test_assert(0 == ioctl(fd, VT_GETSTATE, &vts));
  atomic_printf("VT_GETSTATE returned v_active=%d\n", vts.v_active);

  test_assert(0 == ioctl(fd, KDGKBMODE, &tty_mode));
  atomic_printf("KDGKBMODE returned %d\n", tty_mode);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
