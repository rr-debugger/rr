/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  memset(p, 0xaa, 2 * page_size);
  void* p2 = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  memset(p2, 0xbb, 2 * page_size);
  void* p3 = mremap(p, 2 * page_size, 2 * page_size, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0);
  if (p3 == MAP_FAILED && errno == EINVAL) {
    atomic_puts("MREMAP_DONTUNMAP not present on this kernel, quitting");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(((unsigned char*)p3)[page_size] == 0xaa);
  test_assert(((unsigned char*)p)[page_size] == 0);
  void* p4 = mremap(p3, 2 * page_size, 2 * page_size, MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, p2);
  test_assert(p4 == p2);
  test_assert(((unsigned char*)p4)[page_size] == 0xaa);
  test_assert(((unsigned char*)p3)[page_size] == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
