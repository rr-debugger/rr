/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

void crash(void) { crash_null_deref(); }

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
