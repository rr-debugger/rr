/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* kill_thread(__attribute__((unused)) void* dontcare) {
  atomic_puts("killing ...");
  abort();
  atomic_puts("FAILED: abort() didn't work");
  return NULL; /* not reached */
}

int main(void) {
  pthread_t t;

  pthread_create(&t, NULL, kill_thread, NULL);
  pthread_join(t, NULL);
  atomic_puts("FAILED: joined thread that should have died");
  return 0;
}
