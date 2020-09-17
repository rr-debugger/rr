/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define RR_CLONE_PIDFD 0x1000

int clonefunc(__attribute__((unused)) void* p) {
  exit(77);
  return 0;
}

int main(void) {
  char child_stack[16384];
  pid_t child;
  int status;
  int pidfd = 99;
  int dummy_fds[2];
  pipe(dummy_fds);

  child = clone(clonefunc, (void*)(((uintptr_t)child_stack + sizeof(child_stack)) &
                                   ~((uintptr_t)0x8-1)),
                RR_CLONE_PIDFD | CLONE_VFORK | SIGCHLD, NULL, &pidfd);
  if (child < 0 && errno == EINVAL) {
    atomic_puts("CLONE_PIDFD not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(child >= 0);
  test_assert(pidfd == dummy_fds[1] + 1);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 77 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
