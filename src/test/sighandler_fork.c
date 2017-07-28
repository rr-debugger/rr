/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void sighandler(int sig) {
  atomic_printf("caught signal %d, exiting\n", sig);
}

int main(void) {
  pid_t c;

  signal(SIGCHLD, sighandler);

  atomic_puts("forking child");

  if (0 == (c = fork())) {
    // Child
    usleep(10000);
    atomic_puts("forking grandchild");
    if (0 == (c = fork())) {
      // Grandchild
      usleep(10000);
      exit(0);
    }
    waitpid(c, NULL, 0);
    return 0;
  }

  // Because why not.
  signal(SIGCHLD, NULL);

  waitpid(c, NULL, 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
