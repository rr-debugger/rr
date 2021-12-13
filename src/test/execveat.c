/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  test_assert(argc == 1 || (argc == 2 && !strcmp("self", argv[1])));

  if (argc != 2) {
    char* new_args[] = { argv[0], "self", NULL };
    int ret = syscall(RR_execveat, AT_FDCWD, argv[0], new_args, environ, 0);
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