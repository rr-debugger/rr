/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <random>

int main(void) {
  std::random_device device;
  atomic_printf("Random value = %d\n", device());
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
