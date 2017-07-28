/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 250

int main(void) {
  int i;

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    pid_t child = fork();
    if (0 == child) {
      return 0;
    }
    if (0 > child) {
      atomic_printf("Fork failed with errno %d\n", errno);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
