/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {
  struct timespec ts = { 1, 0 };
  clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
}

static void* start_thread(__attribute__((unused)) void* dontcare) {
  struct timespec ts = { 1, 0 };
  signal(SIGCHLD, handler);
  nanosleep(&ts, NULL);
  return NULL;
}

static void constructor(void) __attribute__((constructor));

static void constructor(void) {
  struct timeval tv;
  pthread_t t;
  gettimeofday(&tv, NULL);

  pthread_create(&t, NULL, start_thread, NULL);
  /* Try to make the thread enter its sleep syscalls */
  struct timespec ts = { 0, 1000000 };
  nanosleep(&ts, NULL);
  /* Trigger signal handler */
  pthread_kill(t, SIGCHLD);
  /* Ensure that signal handler is entered before we proceed to init preload */
  nanosleep(&ts, NULL);
}

void lib_exit_success(void) { atomic_puts("EXIT-SUCCESS"); }
