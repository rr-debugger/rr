/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

// Run two threads until there have been at least a couple
// (approx. 20) context switches between them.
// Races are technically possible, but they'll only increase the
// context switch count, which is fine.
volatile int counter;
static void* start_thread(__attribute__((unused)) void* p) {
  while (1) {
    int c = counter;
    if ((c&1) == 1) counter = c+1;
  }
  
  return NULL;
}

int main(void) {
  pthread_t thread;
  pthread_create(&thread, NULL, start_thread, NULL);
  
  while (1) {
    int c = counter;
    if ((c&1) == 0) counter = c+1;
    if (counter >= 20) break;
  }

  return 0;
}
