/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char *argv[]) {
  if (argc <= 1) {
    atomic_puts("Hi");
  } else {
    atomic_puts(argv[1]);
  }
  return 0;
}
