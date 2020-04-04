/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char *argv[]) {
  pid_t child = fork();
  if (argc > 1 && strcmp(argv[1], "--inner") == 0) {
      atomic_puts("EXIT-SUCCESS");
      return 0;
  }
  test_assert(argc >= 2);

  if (!child) {
    execve(argv[1], &argv[1], environ); // Should not return
    test_assert(0);
  }

  int status;
  wait(&status);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  atomic_puts("EXIT-WAITED");
  return 0;
}
