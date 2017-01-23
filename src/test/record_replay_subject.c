/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p =
      mmap(NULL, page_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);

  test_assert(0 == mprotect(p, page_size, PROT_NONE));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
