/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int do_child(void) {
  test_assert(getpid() == setsid());

  int fd = open("/dev/ptmx", O_RDWR);
  test_assert(fd >= 0);

  atomic_printf("pty ptsname = %s\n", ptsname(fd));

  test_assert(0 == ioctl(fd, TIOCSCTTY, 0));
  test_assert(0 == tcsetpgrp(fd, getpid()));

  struct termios tios;
  test_assert(0 == tcgetattr(fd, &tios));
  tios.c_lflag |= TOSTOP | ECHO;
  test_assert(0 == tcsetattr(fd, TCSANOW, &tios));

  pid_t child = fork();
  if (!child) {
    test_assert(0 == setpgid(0, 0));
    tios.c_lflag &= ~ECHO;
    test_assert(0 == tcsetattr(fd, TCSANOW, &tios));
    return 76;
  }

  int status;
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTTOU);
  return 77;
}

int main(void) {
  // Spawn a child since we need to call setsid() in a non-process-group-leader.
  pid_t child = fork();
  if (!child) {
    return do_child();
  }
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
