/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char** argv) {
  if (argc == 1) {
    char* args[] = { argv[0], "hello", NULL };
    char* envp[] = { NULL };
    execve(argv[0], args, envp);
    test_assert(0);
    return 0;
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
