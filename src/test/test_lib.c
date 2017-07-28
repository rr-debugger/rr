/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* start_thread(__attribute__((unused)) void* dontcare) {
  return NULL;
}

static void constructor(void) __attribute__((constructor));

static void constructor(void) {
  struct timeval tv;
  pthread_t t;
  gettimeofday(&tv, NULL);

  pthread_create(&t, NULL, start_thread, NULL);
  pthread_join(t, NULL);
}

void lib_exit_success(void) { atomic_puts("EXIT-SUCCESS"); }
