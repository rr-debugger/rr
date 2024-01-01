/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) {
  return NULL;
}

int main(void) {
  pthread_t thread;
  pthread_create(&thread, NULL, do_thread, NULL);
  sleep(1);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

