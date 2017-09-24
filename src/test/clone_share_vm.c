/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void break_function(void) {}

static int child(__attribute__((unused)) void* arg) {
  sched_yield();

  syscall(SYS_exit, 77);

  /* NOT REACHED */
  return 0;
}

int main(void) {
  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int tid;
  int status;
  test_assert(stack != MAP_FAILED);

  /* Warning: strace gets the parameter order wrong and will print
     child_tidptr as 0 here. */
  tid = clone(child, stack + stack_size, CLONE_VM | SIGCHLD, NULL, NULL, NULL,
              NULL);

  break_function();

  atomic_printf("clone()d pid: %d\n", tid);
  test_assert(tid > 0);

  test_assert(tid == waitpid(tid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
