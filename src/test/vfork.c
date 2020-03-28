/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

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

  breakpoint();

  atomic_puts("vforker-EXIT-SUCCESS");
  return 0;
}
