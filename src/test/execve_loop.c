/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The runner script bombards us with SIGCHLDs. It's quite likely that one
   of these will be received during an AutoRemoteSyscalls sycall, which is
   what we want to test here. */

int main(__attribute__((unused)) int argc, char* argv[], char* envp[]) {
  int count = atoi(argv[1]);

  if (count > 0) {
    char buf[10];
    sprintf(buf, "%d", count - 1);
    argv[1] = buf;
    execve(argv[0], argv, envp);
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
