/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  pid_t child;
  int status;

  if (argc == 2) {
    atomic_puts("FAILED: this output should be hidden");
    return 77;
  }

  if (0 == (child = fork())) {
    int fd = open("/dev/null", O_WRONLY);
    test_assert(fd >= 0);
    test_assert(STDOUT_FILENO == dup2(fd, STDOUT_FILENO));
    execl(argv[0], argv[0], "step2", NULL);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
