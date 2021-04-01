/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static pid_t pid;
static pid_t tid;

void check_pid(void) {
  assert(pid == getpid());
  atomic_puts("SUCCESS");
}

void check_tid(void) {
  assert(tid == sys_gettid());
  atomic_puts("SUCCESS");
}

void breakpoint(void) {}

static void* thread(__attribute__((unused)) void* dontcare) {
  pid = getpid();
  tid = sys_gettid();

  breakpoint();
  breakpoint();

  return NULL;
}

int main(void) {
  pthread_t t;
  /* Switch to another thread so we can have distinct pid/tids. */
  pthread_create(&t, NULL, thread, NULL);
  pthread_join(t, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;

  /* Not reached */
  check_pid();
  check_tid();
}
