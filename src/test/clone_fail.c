/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int child(__attribute__((unused)) void* arg) {
  /* NOT REACHED */
  syscall(SYS_exit, 77);
  return 0;
}

int main(void) {
  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  /* This will fail due to invalid flags.
     Setting CLONE_UNTRACED here to make sure we test the failure path
     with CLONE_UNTRACED. */
  pid_t ret = clone(child, stack + stack_size, 0xffffffff, NULL, NULL, NULL,
                    NULL);
  test_assert(ret == -1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
