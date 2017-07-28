/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handle_sig(__attribute__((unused)) int sig) {}

int main(void) {
  signal(SIGTTIN, handle_sig);
  kill(getpid(), SIGTTIN);

  signal(SIGTTOU, handle_sig);
  kill(getpid(), SIGTTOU);

  signal(SIGTSTP, handle_sig);
  kill(getpid(), SIGTSTP);

  signal(SIGCONT, handle_sig);
  kill(getpid(), SIGCONT);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
