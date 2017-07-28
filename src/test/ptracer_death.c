/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int status_pipe[2];

static int ptracer(void) {
  pid_t child;
  int status;
  struct timespec ts = { 0, 50000000 };
  int ready_pipe[2];
  char ready = 'R';

  test_assert(0 == pipe(ready_pipe));

  if (0 == (child = fork())) {
    char ch = 0;
    char ok = 'K';

    test_assert(1 == read(ready_pipe[0], &ch, 1));
    test_assert(ch == 'R');
    test_assert(1 == write(status_pipe[1], &ok, 1));
    return 77;
  }

  nanosleep(&ts, NULL);
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  test_assert(1 == write(ready_pipe[1], &ready, 1));
  /* Now just exit, and the child should resume */
  return 44;
}

int main(void) {
  char ch = 0;
  pid_t ptracer_pid;
  int status;

  test_assert(0 == pipe(status_pipe));

  if (0 == (ptracer_pid = fork())) {
    return ptracer();
  }

  test_assert(ptracer_pid == waitpid(ptracer_pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);

  test_assert(1 == read(status_pipe[0], &ch, 1));
  test_assert(ch == 'K');

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
