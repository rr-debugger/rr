/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void first_breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static void second_breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static void* child_thread(void* num_syscallsp) {
  int num_syscalls = (uintptr_t)num_syscallsp;
  int i;

  first_breakpoint();

  atomic_printf("%d: running %d syscalls ...\n", getpid(), num_syscalls);
  for (i = 0; i < num_syscalls; ++i) {
    event_syscall();
  }

  second_breakpoint();

  return NULL;
}

static void child(int num_syscalls) {
  pthread_t t;

  test_assert(0 == pthread_create(&t, NULL, child_thread,
                                  (void*)(uintptr_t)num_syscalls));
  pthread_join(t, NULL);

  exit(0);
}

int main(int argc, char** argv) {
  int num_syscalls;
  pid_t c;
  int status;

  test_assert(argc == 2);
  num_syscalls = atoi(argv[1]);

  if (0 == (c = fork())) {
    child(num_syscalls);
    test_assert("Not reached" && 0);
  }

  atomic_printf("%d: waiting on %d ...\n", getpid(), c);
  test_assert(c == waitpid(c, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
