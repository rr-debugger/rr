/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {
  write(STDOUT_FILENO, "FAILED!\n", 9);
  exit(0);
}

int main(void) {
  sigset_t sigs;
  pid_t child;
  int status;

  signal(SIGSEGV, handler);

  sigemptyset(&sigs);
  sigaddset(&sigs, SIGSEGV);
  sigprocmask(SIG_BLOCK, &sigs, NULL);

  child = fork();
  if (!child) {
    crash_null_deref();
    return 77;
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
