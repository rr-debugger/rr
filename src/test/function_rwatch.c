/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

void read_instructions(void* ptr) {
  char buffer[40];
  memcpy(buffer, ptr, sizeof(buffer));
  write(1, buffer, 0); // Prevent compiler from discarding the above memcpy
}

int main(void) {
  read_instructions(&main);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
