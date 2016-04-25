/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  int i;
  void* p =
      mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  for (i = 0; i < 100000; ++i) {
    test_assert(0 == mprotect(p, PAGE_SIZE, PROT_READ | PROT_WRITE));
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
