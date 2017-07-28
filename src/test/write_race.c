/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_PROCESSES 4
#define NUM_ITERATIONS 500

int main(void) {
  int i;
  int j;

  for (i = 0; i < NUM_PROCESSES; ++i) {
    if (0 == fork()) {
      for (j = 0; j < NUM_ITERATIONS; ++j) {
        char buf[1000];
        sprintf(buf, "Child %d writing line %d\n", i, j);
        write(1, buf, strlen(buf));
      }
      return 0;
    }
  }

  for (i = 0; i < NUM_PROCESSES; ++i) {
    wait(NULL);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
