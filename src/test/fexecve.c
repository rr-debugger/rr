/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  test_assert(argc == 1 || (argc == 2 && !strcmp("self", argv[1])));

  if (argc != 2) {
    int fd = open("/proc/self/exe", O_RDONLY);
    test_assert(fd >= 0);
    char* new_args[] = { argv[0], "self", NULL };
    int ret = syscall(RR_execveat, fd, "", new_args, environ, AT_EMPTY_PATH);
    if (ret < 0 && errno == ENOSYS) {
      atomic_puts("execveat not supported, skipping test");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    test_assert("Not reached" && 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}