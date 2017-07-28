/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {}

static int thread_to_main_fds[2];
static int main_to_child_fds[2];
static int wait_forever_fds[2];

static char ch = 'X';

static void* run_thread(__attribute__((unused)) void* p) {
  test_assert(1 == write(thread_to_main_fds[1], &ch, 1));
  read(wait_forever_fds[0], &ch, 1);
  test_assert(0);
  return NULL;
}

static int run_child(void) {
  test_assert(1 == read(main_to_child_fds[0], &ch, 1));
  /* At this point, the parent's main thread should have exit_group()ed
     and its extra thread should have died but not been scheduled yet.
     Try to take a checkpoint in this state. */
  breakpoint();
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

int main(void) {
  pthread_t thread;
  pid_t child;

  test_assert(0 == pipe(thread_to_main_fds));
  test_assert(0 == pipe(main_to_child_fds));
  test_assert(0 == pipe(wait_forever_fds));

  child = fork();
  if (!child) {
    return run_child();
  }
  atomic_printf("child %d\n", child);
  test_assert(0 == pthread_create(&thread, NULL, run_thread, NULL));

  test_assert(1 == read(thread_to_main_fds[0], &ch, 1));
  /* thread should have blocked on its wait-forever read. Tell the
     child to proceed after we exit_group. */
  test_assert(1 == write(main_to_child_fds[1], &ch, 1));

  return 0;
}
