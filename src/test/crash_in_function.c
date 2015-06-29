/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

void crash(void) { *(int*)NULL = 0; }

int main(int argc, char* argv[]) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
