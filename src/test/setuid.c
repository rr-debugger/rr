/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
  uid_t orig;
  uid_t new;
  int ret;

  if (argc > 1) {
    return 77;
  }

  orig = getuid();
  test_assert(0 == setuid(orig));
  new = orig + 1;
  ret = setuid(new);
  if (ret == -1) {
    test_assert(errno == EPERM);
    atomic_puts("Test did nothing because process does not have CAP_SETUID?");
  } else {
    pid_t child;
    int status;
    test_assert(getuid() == new);
    child = fork();
    if (!child) {
      char* args[] = { argv[0], "dummy", NULL };
      execve(argv[0], args, environ);
      test_assert(0);
    }
    test_assert(child == wait(&status));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }
  atomic_puts("EXIT-SUCCESS");

  return 0;
}
