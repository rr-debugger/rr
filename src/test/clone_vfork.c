/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int not_shared;
static int* shared;

int clonefunc(void* exe) {
  not_shared = 1;
  sched_yield();
  *shared = 1;

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

  size_t page_size = sysconf(_SC_PAGESIZE);
  shared = (int*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_SHARED, -1, 0);

  child = clone(clonefunc, child_stack + sizeof(child_stack),
                CLONE_VFORK | SIGCHLD, (void*)exe);

  /* This should not execute until after the vfork child has execed */
  test_assert(*shared == 1);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  /* We didn't pass CLONE_VM so this should not have changed */
  test_assert(not_shared == 0);

  atomic_puts("clone-vfork-EXIT-SUCCESS");
  return 0;
}
