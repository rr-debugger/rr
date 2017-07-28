/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  int cmd;
  test_assert(argc == 2);
  cmd = atoi(argv[1]);

  if (cmd < 0) {
    kill(getpid(), -cmd);
    return 0;
  }

  return cmd;
}
