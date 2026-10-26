/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* A child sends itself a SIGTRAP. rr can't inject a signal in a SIGTRAP
   signal-stop, so it sends the child a SIGPWR (its desched signal) to get it
   into another signal-stop first. We have rr SIGKILL the child in that
   signal-stop. We do this with a child for which SIGTRAP is fatal and with
   one that has a handler for it. */

static void handler(__attribute__((unused)) int sig) {}

static void run_child(int with_handler) {
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    if (with_handler) {
      test_assert(SIG_ERR != signal(SIGTRAP, handler));
    }
    rr_arm_kill(RRCALL_KILL_BEFORE_GETSIGINFO, SIGPWR, 0);
    kill(getpid(), SIGTRAP);
    exit(77);
  }
  test_assert(child == waitpid(child, &status, 0));
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
    atomic_puts("child was killed");
  } else if (with_handler) {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    atomic_puts("child handled SIGTRAP");
  } else {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTRAP);
    atomic_puts("child got SIGTRAP");
  }
}

int main(void) {
  run_child(0);
  run_child(1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
