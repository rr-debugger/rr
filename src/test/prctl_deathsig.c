/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int child_to_main_fds[2];

static void handle_signal(int sig) {
  test_assert(sig == SIGILL);
  atomic_puts("EXIT-SUCCESS");
  exit(0);
}

static int run_child(void) {
  int sig = 99;
  char ch = 'x';

  signal(SIGILL, handle_signal);

  test_assert(0 == prctl(PR_SET_PDEATHSIG, SIGILL));
  test_assert(0 == prctl(PR_GET_PDEATHSIG, (unsigned long)&sig));
  test_assert(sig == SIGILL);

  test_assert(1 == write(child_to_main_fds[1], &ch, 1));

  sleep(1000000);
  test_assert(0);
  return 0;
}

int main(int argc, char* argv[]) {
  char ch;

  test_assert(0 == pipe(child_to_main_fds));

  if (!fork()) {
    return run_child();
  }
  test_assert(1 == read(child_to_main_fds[0], &ch, 1));
  return 0;
}
