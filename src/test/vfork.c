/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  const char* exe;
  pid_t child;
  int status;

  test_assert(2 == argc);
  exe = argv[1];

  if (0 == (child = vfork())) {
    execl(exe, exe, NULL);
    test_assert("Not reached" && 0);
  }

  atomic_printf("child %d\n", child);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("vforker-EXIT-SUCCESS");
  return 0;
}
