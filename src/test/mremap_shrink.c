/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  void* p = mmap(NULL, 3 * PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  void* p2 = mremap(p, 3 * PAGE_SIZE, 2 * PAGE_SIZE, 0);
  void* p3 = mremap(p, 2 * PAGE_SIZE, PAGE_SIZE, MREMAP_MAYMOVE);

  atomic_printf("%p %p %p\n", p, p2, p3);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
