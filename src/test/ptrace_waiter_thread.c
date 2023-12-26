/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static pid_t child;
static int parent_to_child[2];

static void* do_thread(__attribute__((unused)) void* p) {
  int status;
  /* Make sure this thread (which is not the ptracer thread)
     can read the wait status from the ptracee. */
  int ret = waitpid(-1, &status, 0);
  test_assert(ret == child);
  atomic_puts("EXIT-SUCCESS");
  exit(0);
  return NULL;
}

int main(void) {
  pthread_t thread;
  char ch;
  test_assert(0 == pipe(parent_to_child));

  if (0 == (child = fork())) {
    test_assert(1 == write(parent_to_child[1], "x", 1));
    sleep(1000000);
    return 77;
  }

  test_assert(1 == read(parent_to_child[0], &ch, 1));
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));

  pthread_create(&thread, NULL, do_thread, NULL);
  sleep(10000000);
  return 0;
}
