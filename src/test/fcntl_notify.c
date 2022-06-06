/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char tmp_name[] = "tempXXXXXX";
static int saw_sigio = 0;

void catcher(__attribute__((unused)) int signum) {
  saw_sigio = 1;
}

int main(void) {
  int fd, file_fd;
  mkdtemp(tmp_name);
  signal(SIGIO, catcher);

  fd = open(tmp_name, O_RDONLY | O_DIRECTORY);
  test_assert(fd >= 0);

  fcntl(fd, F_NOTIFY, DN_CREATE);

  file_fd = openat(fd, "foo", O_RDWR | O_CREAT, 0600);
  test_assert(file_fd >= 0);
  test_assert(saw_sigio);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
