/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  int count;
  test_assert(argc <= 2);
  count = argc == 1 ? 100 : atoi(argv[1]);

  if (count > 0) {
    char buf[1000];
    sprintf(buf, "%d", count - 1);
    execlp(argv[0], argv[0], buf, NULL);
    test_assert("Not reached" && 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
