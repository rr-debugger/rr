/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* start_thread(__attribute__((unused)) void* p) {
  sleep(1000);
  return NULL;
}

int main(void) {
  pthread_t thread;

  atomic_puts("ready");

  pthread_create(&thread, NULL, start_thread, NULL);
  atomic_puts("EXIT-SUCCESS");
  while (1) {
  }
  return 0;
}
