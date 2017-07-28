/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  for (i = 0; i < 100; ++i) {
    pid_t child = fork();
    if (child < 0) {
      test_assert(errno == EAGAIN);
    } else if (child == 0) {
      return 77;
    } else {
      int status;
      test_assert(child == wait(&status));
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    }
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
