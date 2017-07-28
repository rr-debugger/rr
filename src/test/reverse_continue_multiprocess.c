/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {}

static int parent_to_child[2];
static int child_to_parent[2];

int main(void) {
  pid_t pid;
  int status;
  int i;
  char ch;

  test_assert(0 == pipe(parent_to_child));
  test_assert(0 == pipe(child_to_parent));

  /* Force ping-ponging between parent and child. At each iteration the
     child receives a signal. We debug the parent process; the signals
     being received by the child while reverse-executing the parent
     should be ignored at a low enough level they don't impact the
     performance of reverse-continue. */
  breakpoint();
  pid = fork();
  if (0 == pid) {
    for (i = 0; i < 1000; ++i) {
      char ch;
      test_assert(1 == read(parent_to_child[0], &ch, 1) && ch == 'y');
      kill(getpid(), SIGCHLD);
      test_assert(1 == write(child_to_parent[1], "x", 1));
    }
    return 77;
  }

  for (i = 0; i < 1000; ++i) {
    test_assert(1 == write(parent_to_child[1], "y", 1));
    test_assert(1 == read(child_to_parent[0], &ch, 1) && ch == 'x');
  }

  test_assert(pid == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  breakpoint();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
