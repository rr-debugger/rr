/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  void* p =
      mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);

  test_assert(-1 == madvise(p, PAGE_SIZE, MADV_FREE));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
