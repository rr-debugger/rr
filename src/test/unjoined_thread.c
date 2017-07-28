/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* thread(__attribute__((unused)) void* unused) {
  sleep(-1);
  return NULL;
}

int main(void) {
  pthread_t t;

  pthread_create(&t, NULL, thread, NULL);
  /* Don't join |t|. */

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
