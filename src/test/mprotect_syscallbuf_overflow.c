/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p =
      mmap(NULL, page_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  for (i = 0; i < 10000; ++i) {
    test_assert(0 == mprotect(p, page_size, PROT_READ | PROT_WRITE));
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
