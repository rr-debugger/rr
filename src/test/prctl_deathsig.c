/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int grandchild_to_child_fds[2];
static int grandchild_to_main_fds[2];

static void handle_signal(int sig) {
  test_assert(sig == SIGILL);
  atomic_puts("EXIT-SUCCESS");
  /* Signal main to go ahead and exit */
  test_assert(1 == write(grandchild_to_main_fds[1], "x", 1));
  exit(0);
}

static int run_grandchild(void) {
  int sig = 99;

  signal(SIGILL, handle_signal);

  test_assert(0 == prctl(PR_SET_PDEATHSIG, SIGILL));
  test_assert(0 == prctl(PR_GET_PDEATHSIG, (unsigned long)&sig));
  test_assert(sig == SIGILL);

  /* Signal child to go ahead and exit.
     This will trigger our SIGILL handler. */
  test_assert(1 == write(grandchild_to_child_fds[1], "y", 1));

  sleep(1000000);
  test_assert(0);
  return 0;
}

static int run_child(void) {
  char ch;
  if (!fork()) {
    return run_grandchild();
  }
  test_assert(1 == read(grandchild_to_child_fds[0], &ch, 1));
  return 0;
}

int main(void) {
  char ch;

  test_assert(0 == pipe(grandchild_to_child_fds));
  test_assert(0 == pipe(grandchild_to_main_fds));

  if (!fork()) {
    return run_child();
  }
  test_assert(1 == read(grandchild_to_main_fds[0], &ch, 1));
  return 0;
}
