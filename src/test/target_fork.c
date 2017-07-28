/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void bad_breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static void good_breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

int main(int argc, char* argv[]) {
  int num_syscalls;
  int child;
  int i;

  bad_breakpoint();

  test_assert(argc == 2);
  num_syscalls = atoi(argv[1]);

  atomic_printf("%d: running %d syscalls ...\n", getpid(), num_syscalls);
  for (i = 0; i < num_syscalls; ++i) {
    event_syscall();
  }

  if (0 == (child = fork())) {
    good_breakpoint();
    exit(0);
  }

  atomic_printf("child %d\n", child);

  waitpid(child, NULL, 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
