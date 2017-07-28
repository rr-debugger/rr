/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("/dev/ptmx", O_RDONLY);
  pid_t child;
  int ret;
  int status;
  int* arg;
  test_assert(fd >= 0);

  atomic_printf("pty ptsname = %s\n", ptsname(fd));

  ALLOCATE_GUARD(arg, 'a');
  test_assert(0 == ioctl(fd, TIOCGPKT, arg));
  VERIFY_GUARD(arg);
  test_assert(*arg == 0);

  test_assert(0 == ioctl(fd, TIOCPKT, arg));

  ALLOCATE_GUARD(arg, 'b');
  test_assert(0 == ioctl(fd, TIOCGPTN, arg));
  VERIFY_GUARD(arg);
  atomic_printf("pty number = %d\n", *arg);

  ALLOCATE_GUARD(arg, 'c');
  test_assert(0 == ioctl(fd, TIOCGPTLCK, arg));
  VERIFY_GUARD(arg);
  test_assert(*arg == 1);

  test_assert(0 == ioctl(fd, TIOCSPTLCK, arg));

  test_assert(0 == ioctl(fd, TCXONC, TCOOFF));
  test_assert(0 == ioctl(fd, TCFLSH, TCIFLUSH));

  child = fork();
  if (!child) {
    test_assert(getpid() == setsid());

    test_assert(0 == ioctl(fd, TIOCSCTTY, 0));
    ioctl(fd, TIOCNOTTY, 0);
    // The above ioctl can legitimately fail. If so, fake it.
    kill(getpid(), SIGHUP);
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGHUP);

  ret = ioctl(fd, TIOCSTI, "x");
  test_assert(ret >= 0 || errno == EPERM);

  test_assert(0 == ioctl(fd, TIOCEXCL, 0));
  ALLOCATE_GUARD(arg, 'd');
  test_assert(0 == ioctl(fd, TIOCGEXCL, arg));
  VERIFY_GUARD(arg);
  test_assert(*arg == 1);
  test_assert(0 == ioctl(fd, TIOCNXCL, 0));

  ALLOCATE_GUARD(arg, 'e');
  test_assert(0 == ioctl(fd, TIOCGETD, arg));
  VERIFY_GUARD(arg);
  atomic_printf("pty TIOCGETD = %d\n", *arg);
  test_assert(0 == ioctl(fd, TIOCSETD, arg));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
