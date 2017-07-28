/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int do_child(void) {
  int fd = open("/dev/zero", O_RDONLY);
  int i;
  char ch;

  test_assert(fd >= 0);
  for (i = 0; i < 10000; ++i) {
    test_assert(1 == read(fd, &ch, 1));
    sched_yield();
  }
  return 77;
}

int main(void) {
  pid_t child;
  int status;
  int i;

  child = fork();
  if (!child) {
    return do_child();
  }

  for (i = 0; i < 100; ++i) {
    kill(child, SIGSTOP);
    sched_yield();
    kill(child, SIGCONT);
    sched_yield();
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
