/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  int fd = open("/dev/ptmx", O_RDONLY);
  int ret;
  int* arg;
  test_assert(fd >= 0);

  atomic_printf("pty ptsname = %s\n", ptsname(fd));

  ALLOCATE_GUARD(arg, 'a');
  test_assert(0 == ioctl(fd, TIOCGPKT, arg));
  VERIFY_GUARD(arg);
  test_assert(*arg == 0);

  test_assert(0 == ioctl(fd, TIOCGPTN, arg));
  VERIFY_GUARD(arg);
  atomic_printf("pty number = %d\n", *arg);

  test_assert(0 == ioctl(fd, TIOCGPTLCK, arg));
  VERIFY_GUARD(arg);
  test_assert(*arg == 1);

  test_assert(0 == ioctl(fd, TIOCSPTLCK, arg));

  test_assert(0 == ioctl(fd, TCXONC, TCOOFF));
  test_assert(0 == ioctl(fd, TCFLSH, TCIFLUSH));

  ret = ioctl(fd, TIOCSTI, "x");
  test_assert(ret >= 0 || errno == EPERM);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
