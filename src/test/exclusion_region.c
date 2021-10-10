/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
#ifdef __x86_64__
  size_t page_size = sysconf(_SC_PAGESIZE);
  uintptr_t granularity = ((uintptr_t)2)*1024*1024*1024*1024;
  char* addr = (char*)granularity;
  int failed_to_allocate_in_some_region = 0;
  while (addr < (char*)(((uintptr_t)1) << 47)) {
    int succeeded = 0;
    for (int i = 0; i < 16; ++i) {
      char* addr2 = addr + i * page_size;
      void* p = mmap(addr2, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (p == addr2) {
        succeeded = 1;
      }
      munmap(p, 4096);
    }
    if (!succeeded) {
      atomic_printf("All allocations around %p failed\n", addr);
      failed_to_allocate_in_some_region = 1;
    }
    addr += granularity;
  }
  test_assert(failed_to_allocate_in_some_region);
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
