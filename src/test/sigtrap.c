/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handle_sigtrap(__attribute__((unused)) int sig) {
  atomic_puts("EXIT-SUCCESS");
  _exit(0);
}

static void* dummy_thread(__attribute__((unused)) void* p) { return NULL; }

int main(void) {
  int status;
  pthread_t thread;

  signal(SIGTRAP, handle_sigtrap);

  /* Test that if a process gets our SIGTRAP handler then that
     works OK. */
  if (!fork()) {
    return 77;
  }
  test_assert(wait(&status) >= 0);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  pthread_create(&thread, NULL, dummy_thread, NULL);
  pthread_join(thread, NULL);

  atomic_puts("raising SIGTRAP ...");

  raise(SIGTRAP);

  return 0;
}
