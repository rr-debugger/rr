/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* start_thread(__attribute__((unused)) void* p) {
  test_assert(11 == dup2(STDOUT_FILENO, 11));
  test_assert(14 == write(11, "EXIT-SUCCESS\n", 14));

  return NULL;
}

int main(void) {
  pthread_t thread;

  pthread_create(&thread, NULL, start_thread, NULL);
  pthread_exit(NULL);

  return 0;
}
