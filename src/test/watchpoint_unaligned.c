/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static uint16_t* p2;
static uint32_t* p4;
static uint64_t* p8;

static void breakpoint(void) {}

int main(void) {
  char* m = xmalloc(0x1000);
  void* unaligned_p = (void*)((uintptr_t)m | 0xff);

  p2 = unaligned_p;
  p4 = unaligned_p;
  p8 = unaligned_p;

  breakpoint();
  *p2 = 1;

  breakpoint();
  *p4 = 2;

  breakpoint();
  *p8 = 3;

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
