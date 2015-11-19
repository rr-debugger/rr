/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int clonefunc(void* exe) {
  execl(exe, exe, NULL);
  test_assert("Not reached" && 0);
  return 0;
}

int main(int argc, char* argv[]) {
  char child_stack[16384];
  const char* exe;
  pid_t child;
  int status;

  test_assert(2 == argc);
  exe = argv[1];

  child = clone(clonefunc, child_stack + sizeof(child_stack),
                CLONE_VFORK | SIGCHLD, (void*)exe);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("clone-vfork-EXIT-SUCCESS");
  return 0;
}
