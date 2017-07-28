/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  const char* exe_image;
  int child;

  test_assert(argc == 2);
  exe_image = argv[1];

  atomic_printf("%d: forking and exec'ing %s...\n", getpid(), exe_image);
  if (0 == (child = fork())) {
    execl(exe_image, exe_image, NULL);
    test_assert("Not reached; execl() failed." && 0);
  }

  atomic_printf("child %d\n", child);

  waitpid(child, NULL, 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
