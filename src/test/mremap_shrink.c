/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p = mmap(NULL, 3 * page_size, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  void* p2 = mremap(p, 3 * page_size, 2 * page_size, 0);
  void* p3 = mremap(p, 2 * page_size, page_size, MREMAP_MAYMOVE);

  atomic_printf("%p %p %p\n", p, p2, p3);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
