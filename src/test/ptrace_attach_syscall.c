/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int parent_to_child_fds[2];

int main(void) {
  pid_t child;
  int status;
  int ret = pipe(parent_to_child_fds);
  test_assert(ret == 0);

  if (0 == (child = fork())) {
    char ch;
    read(parent_to_child_fds[0], &ch, 1);
    return 77;
  }

  struct timespec ts = { 0, 50000000 };
  nanosleep(&ts, NULL);

  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  write(parent_to_child_fds[1], "x", 1);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
