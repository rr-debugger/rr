/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  void* prev;
  void* start = sbrk(0);
  test_assert((intptr_t)start != -1);
  test_assert(start == sbrk(111));

  memset(start, 0xaa, 111);

  prev = sbrk(1000000);
  test_assert(prev != (void*)-1);
  test_assert(0 == brk(prev));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
