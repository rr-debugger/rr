/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  void* prev;
  void* start = sbrk(0);
  test_assert((intptr_t)start != -1);
  void* start_after_allocation = sbrk(111);
  if (start_after_allocation == (void*)-1) {
    // We have seen an intermittent failure here on 32-bit :-(
    test_assert(errno == ENOMEM);
    test_assert(sizeof(void*) == 4);
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(start == start_after_allocation);
  memset(start, 0xaa, 111);

  prev = sbrk(1000000);
  if (prev == (void*)-1) {
    test_assert(errno == ENOMEM);
    test_assert(sizeof(void*) == 4);
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(0 == brk(prev));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
