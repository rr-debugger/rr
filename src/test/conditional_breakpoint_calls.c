/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int counter;
int dot_counter;

int checker(void) {
  ++counter;
  return 0;
}

static void print_dot(void) {
  atomic_printf(".");
  ++dot_counter;
}

int main(void) {
  int i;

  for (i = 0; i < 10; ++i) {
    print_dot();
  }

  atomic_puts("\nEXIT-SUCCESS");
  return 0;
}
