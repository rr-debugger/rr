/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {}

int main(void) {
  sigset_t sigs;

  sigemptyset(&sigs);
  sigaddset(&sigs, SIGKILL);
  sigprocmask(SIG_BLOCK, &sigs, NULL);
  signal(SIGKILL, SIG_IGN);
  signal(SIGKILL, handler);

  sigemptyset(&sigs);
  sigaddset(&sigs, SIGSTOP);
  sigprocmask(SIG_BLOCK, &sigs, NULL);
  signal(SIGSTOP, SIG_IGN);
  signal(SIGSTOP, handler);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
