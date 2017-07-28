/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  char* p;

  /* map 3 pages since the first page will be made into a guard page by the
     kernel */
  size_t page_size = sysconf(_SC_PAGESIZE);
  p = mmap(NULL, page_size * 3, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
  test_assert(p != MAP_FAILED);

  test_assert(
      0 == mprotect(p + page_size * 2, page_size, PROT_NONE | PROT_GROWSDOWN));

  test_assert(-1 == mprotect(p + 1, page_size, PROT_NONE | PROT_GROWSDOWN));
  test_assert(EINVAL == errno);

  p = (char*)(((uintptr_t)main) & ~((uintptr_t)page_size - 1));
  test_assert(-1 ==
              mprotect(p, page_size, PROT_READ | PROT_EXEC | PROT_GROWSDOWN));
  test_assert(EINVAL == errno);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
