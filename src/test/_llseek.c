/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(__attribute__((unused)) int argc, char* argv[]) {
  int fd = open(argv[0], O_RDONLY);
#ifdef SYS__llseek
  loff_t result = -1234;
#endif
  test_assert(fd >= 0);
#ifdef SYS__llseek
  test_assert(syscall(SYS__llseek, fd, 0, 0, &result, SEEK_SET) == 0);
  test_assert(result == 0);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
