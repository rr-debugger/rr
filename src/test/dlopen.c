/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  void* h = dlopen("libX11.so", RTLD_LAZY);
  if (h) {
    dlclose(h);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
