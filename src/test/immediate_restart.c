/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int child;

  atomic_printf("%d: forking...\n", getpid());
  if (0 == (child = fork())) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  atomic_printf("child %d\n", child);

  waitpid(child, NULL, 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
