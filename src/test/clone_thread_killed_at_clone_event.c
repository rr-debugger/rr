/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Our child has rr SIGKILL it at the PTRACE_EVENT_CLONE stop of its
   pthread_create(), before rr reads the new thread's tid. The new thread
   dies with the child, and rr never hears of it before it does. */

static void* thread_fn(__attribute__((unused)) void* p) { return NULL; }

int main(void) {
  pid_t child;
  int status;

  child = fork();
  if (!child) {
    pthread_t thread;
    /* Arm the kill after the fork(), so that the fork() doesn't trigger it. */
    rr_arm_kill(RRCALL_KILL_AT_CLONE_EVENT, 0, 0);
    test_assert(0 == pthread_create(&thread, NULL, thread_fn, NULL));
    test_assert(0 == pthread_join(thread, NULL));
    _exit(0);
  }
  test_assert(child == waitpid(child, &status, 0));
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
    atomic_puts("child was killed");
  } else {
    /* Without rr */
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
