/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static SyscallWrapper delayed_syscall;

static void* run_child(__attribute__((unused)) void* arg) {
  /* context-switch events will happen during our long delay in the syscallbuf.
     These will be queued and must be processed during exit.
     In general these could be other signals that must not be dropped
     so we want to handle them. */
  struct syscall_info exit_syscall = { SYS_exit, { 0, 0, 0, 0, 0, 0 } };
  delayed_syscall(&exit_syscall);
  test_assert(0 && "Should not reach here!");
  return 0;
}

int main(void) {
  pthread_t thread;

  delayed_syscall = get_delayed_syscall();
  if (delayed_syscall == default_syscall_wrapper) {
    atomic_puts("syscallbuf not loaded");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  pthread_create(&thread, NULL, run_child, NULL);
  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
